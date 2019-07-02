// Command tlstun implements basic VPN over TLS (both client and server).
//
// Client part is expected to be run locally and used by local services as
// a socks5 proxy. Client establishes TLS session to the server running on some
// remote host that performs outgoing requests on behalf of requests made to the
// client.
//
// Client and server authenticate each other with certificates which can be
// created with openssl or https://github.com/artyom/gencert
//
// Usage example
//
// Generate server and client side certificates, they can be signed by the same
// CA and saved using PEM encoding into a single file. Certificate keys should
// also be saved as a separate PEM-encoded files. With gencert tool from
// https://github.com/artyom/gencert this can be done as:
//
// 	gencert -hosts my.domain.tld
//
// This produces five files in the current directory: client certificate + key
// pair, another pair for the server and a certificate authority certificate.
// Note that my.domain.tld should point to the host you plan running server part
// of tlstun.
//
// Now configure tlstun to run on the server that could be reached at
// my.domain.tld like this:
//
// 	tlstun server -addr=:9000 -ca=ca.pem \
// 		-cert=server-cert.pem -key=server-key.pem
//
// The client part is expected to be running locally (on a laptop/workstation,
// etc.):
//
//	tlstun client -addr=127.0.0.1:1080 -ca=ca.pem \
//		-cert=client-cert.pem -key=client-key.pem \
//		my.domain.tld:9000
//
// Client is now listening on localhost port 1080 and local software can be
// configured to use this endpoint as a socks5 proxy.
//
// Client may be configured to work with multiple servers:
//
//	tlstun client -addr=127.0.0.1:1080 -ca=ca.pem \
//		-cert=client-cert.pem -key=client-key.pem \
//		my.domain.tld:9000 other.domain.tld:9000
//
// By default client will periodically evaluate all endpoints and prefer one
// which replies first. This check may be disabled with -no-check flag.
//
// Instead of listing endpoints directly, client may discover them from SRV DNS
// records. If -discover=domain.tld flag is set, client ignores any endpoints
// given on the command line and instead looks up SRV record
// _tlstun._tcp.domain.tld, which must follow standard format to specify
// host/port pairs.
//
// HTTPS compatible mode
//
// Server may be configured to automatically issue certificate from ACME
// provider (currently is's Let's Encrypt). For this to work, server must be
// exposed over port 443 and it also doubles as an https endpoint. By default it
// replies with 404 Not Found, but can optionally be configured to serve static
// files from file system directory:
//
//	tlstun server -addr=:443 -ca=ca.pem -acme \
//		-acme-domain=domain.tld -acme-email=you@domain.tld \
//		-acme-cache=/var/cache/acme \
//		-httproot=/var/www/domain.tld
//
// Server may also be run with -dns-tls flag, which enables resolving via
// DNS-over-TLS providers (currently Cloudflare and Quad9).
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	socks5 "github.com/armon/go-socks5"
	"github.com/artyom/autoflags"
	"github.com/artyom/dot"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/sync/errgroup"
)

func main() {
	clientFlags := flag.NewFlagSet("client", flag.ExitOnError)
	clientFlags.Usage = func() { usageClient(clientFlags) }
	clientArgs := clientArgs{Addr: "localhost:1080"}
	autoflags.DefineFlagSet(clientFlags, &clientArgs)

	serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
	serverFlags.Usage = func() { usageServer(serverFlags) }
	serverArgs := serverArgs{Addr: ":443"}
	autoflags.DefineFlagSet(serverFlags, &serverArgs)

	if len(os.Args) < 2 {
		usageMain(serverFlags, clientFlags)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		serverFlags.Parse(os.Args[2:])
		err = runServer(serverArgs)
	case "client":
		clientFlags.Parse(os.Args[2:])
		err = runClient(clientArgs, clientFlags.Args())
	default:
		usageMain(serverFlags, clientFlags)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runClient(args clientArgs, servers []string) error {
	if args.Addr == "" {
		return errors.New("addr cannot be empty")
	}
	if args.Cert == "" || args.Key == "" {
		return errors.New("both cert and key must be set")
	}
	if !args.SystemCAs && args.CA == "" {
		return errors.New("at least one source of CAs should be enabled, see -ca and -system-ca flags")
	}
	if args.Discover == "" && len(servers) == 0 {
		return errors.New("either set at least one server endpoint or specify domain for automatic discovery")
	}
	tlsConfig, err := clientTLSConfig(args.Cert, args.Key, args.CA, args.SystemCAs)
	if err != nil {
		return err
	}
	var r *net.Resolver
	if args.DoT {
		r = anyResolver(dot.Cloudflare(), dot.Quad9())
	}
	if args.Discover != "" {
		lookup := func(service, proto, name string) (string, []*net.SRV, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return r.LookupSRV(ctx, service, proto, name)
		}
		cname, recs, err := lookup("tlstun", "tcp", args.Discover)
		if te, ok := err.(interface{ Temporary() bool }); ok && te.Temporary() {
			if cached := loadDiscoverCache(args.Discover); len(cached) > 0 {
				log.Printf("using cached server list, temporary discover failure: %v", err)
				servers = cached
				goto hasServers
			}
		}
		if err != nil {
			return err
		}
		if len(recs) == 0 {
			return fmt.Errorf("no server endpoints discovered at %q", cname)
		}
		servers = servers[:0]
		for _, rec := range recs {
			servers = append(servers, net.JoinHostPort(rec.Target,
				strconv.FormatUint(uint64(rec.Port), 10)))
		}
		saveDiscoverCache(args.Discover, servers)
	}
hasServers:
	for _, addr := range servers {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("%q is not a valid address: %v", addr, err)
		}
		if host == "" || port == "" {
			return fmt.Errorf("%q is not a valid address", addr)
		}
	}
	cl := &client{
		cfg:      tlsConfig,
		resolver: r,
		addrs:    servers,
	}
	ln, err := net.Listen("tcp", args.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if len(servers) > 1 && !args.NoCheck {
		go cl.healthCheck(ctx)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go cl.handleConn(conn)
	}
}

type client struct {
	cfg      *tls.Config
	resolver *net.Resolver // nil for default system resolver

	mu    sync.Mutex
	addrs []string
}

func (cl *client) handleConn(conn net.Conn) error {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(3 * time.Minute)
	}
	defer conn.Close()
	rconn, err := cl.dialAny()
	if err != nil {
		return err
	}
	defer rconn.Close()
	errc := make(chan error, 1)
	go proxyCopy(errc, rconn, conn)
	go proxyCopy(errc, conn, rconn)
	return <-errc
}

func (cl *client) dialAny() (net.Conn, error) {
	cl.mu.Lock()
	addrs := make([]string, len(cl.addrs))
	copy(addrs, cl.addrs)
	cl.mu.Unlock()
	var err error
	var conn net.Conn
	for i, addr := range addrs {
		if conn, err = cl.dial(addr); err == nil {
			if i > 0 {
				cl.promoteAddr(addr)
			}
			return conn, err
		}
	}
	return nil, err
}

func (cl *client) dial(addr string) (net.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 3 * time.Minute,
		Resolver:  cl.resolver,
	}, "tcp", addr, cl.cfg)
}

func (cl *client) promoteAddr(addr string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	for i, s := range cl.addrs {
		if s != addr {
			continue
		}
		if i == 0 {
			return
		}
		cl.addrs[0], cl.addrs[i] = cl.addrs[i], cl.addrs[0]
		return
	}
}

func (cl *client) healthCheck(ctx context.Context) {
	timeCh := time.After(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timeCh:
		}
		switch cl.serverCheck() {
		case nil:
			timeCh = time.After(time.Duration(5+rand.Intn(5)) * time.Minute)
		default:
			timeCh = time.After(time.Duration(2+rand.Intn(3)) * time.Minute)
		}
	}
}

func (cl *client) serverCheck() error {
	cl.mu.Lock()
	res := make([]struct {
		addr string
		d    time.Duration
		err  error
	}, len(cl.addrs))
	for i, addr := range cl.addrs {
		res[i].addr = addr
	}
	cl.mu.Unlock()
	var g errgroup.Group
	for i := range res {
		i := i
		g.Go(func() error {
			begin := time.Now()
			conn, err := cl.dial(res[i].addr)
			if err != nil {
				res[i].err = err
				return err
			}
			res[i].d = time.Since(begin)
			conn.Close()
			return nil
		})
	}
	err := g.Wait()
	sort.Slice(res, func(i, j int) bool {
		if res[i].err != nil || res[j].err != nil {
			return false
		}
		return res[i].d < res[j].d
	})
	cl.mu.Lock()
	for i := range res {
		cl.addrs[i] = res[i].addr
	}
	cl.mu.Unlock()
	return err
}

type clientArgs struct {
	Addr      string `flag:"addr,host:port to listen"`
	Discover  string `flag:"discover,domain to discover server endpoint(s) from DNS SRV records"`
	Cert      string `flag:"cert,path to PEM-encoded certificate"`
	Key       string `flag:"key,path to PEM-encoded certificate key"`
	CA        string `flag:"ca,path to PEM-encoded CA certificate used to verify server certificate"`
	SystemCAs bool   `flag:"system-ca,allow server certificate be signed by one of the system CAs"`
	DoT       bool   `flag:"dns-tls,use DNS-over-TLS (Cloudflare and Quad9)"`
	NoCheck   bool   `flag:"no-check,do not evaluate server health periodically to pick the best one"`
}

func runServer(args serverArgs) error {
	if args.Addr == "" {
		return errors.New("addr cannot be empty")
	}
	if !args.ACME && (args.Cert == "" || args.Key == "") {
		return errors.New("both cert and key must be set or acme setup used")
	}
	if args.CA == "" {
		return errors.New("ca cannot be empty")
	}
	if args.ACME && (args.AcmeDomain == "" ||
		args.AcmeEmail == "" || args.AcmeCache == "") {
		return errors.New("acme mode requires providing values to all acme-* flags")
	}
	if args.ACME && !strings.HasSuffix(args.Addr, ":443") &&
		!strings.HasSuffix(args.Addr, ":https") {
		return errors.New("acme mode can only be used if service listens on port 443 (https)")
	}
	var tlsConfig *tls.Config
	var err error
	switch {
	case args.ACME:
		if err := os.MkdirAll(args.AcmeCache, 0700); err != nil {
			return err
		}
		tlsConfig, err = acmeTLSConfig(args.AcmeDomain, args.AcmeEmail, args.AcmeCache, args.CA)
	default:
		tlsConfig, err = serverTLSConfig(args.Cert, args.Key, args.CA)
	}
	if err != nil {
		return err
	}

	var r *net.Resolver
	if args.DoT {
		r = anyResolver(dot.Cloudflare(), dot.Quad9())
	}
	socksServer, err := socks5.New(&socks5.Config{
		Dial: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 3 * time.Minute,
			Resolver:  r,
		}).DialContext,
		Resolver: newSocksResolver(r),
		Logger:   log.New(ioutil.Discard, "", 0),
	})
	if err != nil {
		panic(err)
	}

	ln, err := net.Listen("tcp", args.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	ln = tcpKeepAliveListener{ln.(*net.TCPListener)}

	if !args.ACME { // easy setup
		tln := tls.NewListener(ln, tlsConfig)
		for {
			conn, err := tln.Accept()
			if err != nil {
				return err
			}
			go socksServer.ServeConn(conn)
		}
	}
	// more arcane setup
	httpServer := &http.Server{
		Handler:           http.NotFoundHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      time.Minute, // TODO
		TLSConfig:         tlsConfig,
	}
	if args.DocRoot != "" {
		httpServer.Handler = http.FileServer(http.Dir(args.DocRoot))
	}
	if err := http2.ConfigureServer(httpServer, nil); err != nil {
		return err
	}
	disp := &dispatcher{
		Listener: ln,
		ch:       make(chan acceptRes),
		cfg:      httpServer.TLSConfig,
		socks:    socksServer,
	}
	go disp.loop()
	return httpServer.Serve(disp)
}

type dispatcher struct {
	net.Listener
	ch        chan acceptRes
	acceptErr error
	cfg       *tls.Config
	socks     *socks5.Server
}

func (srv *dispatcher) loop() {
	for {
		conn, err := srv.Listener.Accept()
		if err != nil {
			srv.acceptErr = err
			srv.ch <- acceptRes{err: err}
			close(srv.ch)
			return
		}
		// do TLS handshake in a separate goroutine to avoid blocking
		// accept loop
		go func(conn net.Conn) {
			tlsConn := tls.Server(conn, srv.cfg)
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				return
			}
			switch srv.cfg.ClientAuth {
			case tls.VerifyClientCertIfGiven, tls.RequireAndVerifyClientCert:
			default:
				srv.ch <- acceptRes{conn: tlsConn}
				return
			}
			if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
				srv.ch <- acceptRes{conn: tlsConn}
				return
			}
			// peer certificates is non empty; assuming that
			// srv.cfg.ClientAuth is either VerifyClientCertIfGiven
			// or RequireAndVerifyClientCert, we can safely rely
			// that it was verified during handshake
			srv.socks.ServeConn(tlsConn)
		}(conn)
	}
}

func (srv *dispatcher) Accept() (net.Conn, error) {
	if res, ok := <-srv.ch; ok {
		return res.conn, res.err
	}
	if srv.acceptErr == nil {
		panic("dispatcher.acceptErr is nil while dispatcher.ch is closed")
	}
	return nil, srv.acceptErr
}

type acceptRes struct {
	conn net.Conn
	err  error
}

func acmeTLSConfig(domain, email, cacheDir, caFile string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	b, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("no certificates found in %q", caFile)
	}
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(domain),
		Email:      email,
	}
	cfg := m.TLSConfig()
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	return cfg, nil
}

func serverTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	b, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("no certificates found in %q", caFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		MinVersion:   tls.VersionTLS12,

		PreferServerCipherSuites: true,
	}, nil
}

type serverArgs struct {
	Addr       string `flag:"addr,host:port to listen"`
	Cert       string `flag:"cert,path to PEM-encoded certificate"`
	Key        string `flag:"key,path to PEM-encoded certificate key"`
	CA         string `flag:"ca,path to PEM-encoded CA certificate used to verify client certificate"`
	ACME       bool   `flag:"acme,automatically issue server certificate, addr must have port 443 then"`
	AcmeDomain string `flag:"acme-domain,domain to issue certificate for"`
	AcmeEmail  string `flag:"acme-email,email presented to ACME API (may be used for technical feedback)"`
	AcmeCache  string `flag:"acme-cache,directory to store ACME-related files"`
	DocRoot    string `flag:"httproot,if non-empty, this directory will be served as https site"`
	DoT        bool   `flag:"dns-tls,use DNS-over-TLS (Cloudflare and Quad9)"`
}

func clientTLSConfig(certFile, keyFile, caFile string, useSystemCAs bool) (*tls.Config, error) {
	if !useSystemCAs && caFile == "" {
		return nil, errors.New("no CA source provided")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	var pool *x509.CertPool
	if useSystemCAs {
		if pool, err = x509.SystemCertPool(); err != nil {
			return nil, err
		}
	}
	if caFile != "" {
		b, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("no certificates found in %q", caFile)
		}
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            pool,
		CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
		NextProtos:         []string{"h2", "http/1.1"}, // mimic https client
	}, nil
}

func anyResolver(resolvers ...*net.Resolver) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if fn := resolvers[rand.Intn(len(resolvers))].Dial; fn != nil {
				return fn(ctx, network, address)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
	}
}

func proxyCopy(errc chan<- error, dst, src net.Conn) {
	_, err := io.Copy(dst, src)
	errc <- err
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

func newSocksResolver(r *net.Resolver) socks5.NameResolver {
	if r == nil {
		return socks5.DNSResolver{}
	}
	return socksResolver{r}
}

type socksResolver struct {
	*net.Resolver
}

func (sr socksResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ips, err := sr.Resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	if len(ips) == 0 {
		return ctx, nil, &net.DNSError{Err: "no such host", Name: name}
	}
	return ctx, ips[0].IP, nil
}

func loadDiscoverCache(name string) []string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return nil
	}
	file := filepath.Join(dir, "tlstun",
		fmt.Sprintf("%x", sha256.Sum256([]byte(name))))
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}
	return strings.Split(string(b), "\n")
}

func saveDiscoverCache(name string, vals []string) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return
	}
	file := filepath.Join(dir, "tlstun",
		fmt.Sprintf("%x", sha256.Sum256([]byte(name))))
	_ = os.MkdirAll(filepath.Dir(file), 0700)
	_ = ioutil.WriteFile(file, []byte(strings.Join(vals, "\n")), 0600)
}

func usageMain(serverFlags, clientFlags *flag.FlagSet) {
	fmt.Fprint(os.Stderr, usageHead)
	fmt.Fprint(os.Stderr, "\nTo run client:\n\n")
	usageClient(clientFlags)
	fmt.Fprint(os.Stderr, "\nTo run server:\n\n")
	usageServer(serverFlags)
}

func usageClient(flags *flag.FlagSet) {
	fmt.Fprintln(os.Stderr, usageClientHead)
	flags.PrintDefaults()
	fmt.Fprint(os.Stderr, usageClientTail)
}

func usageServer(flags *flag.FlagSet) {
	fmt.Fprintln(os.Stderr, usageServerHead)
	flags.PrintDefaults()
	fmt.Fprint(os.Stderr, usageServerTail)
}

const usageHead = `Usage: tlstun client [client flags] [server list]
       tlstun server [server flags]
`

const usageClientHead = `tlstun client [client flags] [server list]
`

const usageClientTail = `
Either non-empty server list or -discover=domain.tld flag must be set. Server
addresses must be of host:port form. If -discover set to example.com, program
will look up SRV record(s) _tlstun._tcp.example.com to get server list.

Either one of -system-ca, -ca=file.pem or both flags must be set.
`

const usageServerHead = `tlstun server [server flags]
`

const usageServerTail = `
Server can be run either with directly provided certificate (usually it's
self-signed) by -cert and -key flags, or with automated certificate issue via
ACME (Automatic Certificate Management Environment) provider, which requires
setting all of -acme-* flags. In the latter case server must be exposed over 443
(https) port.

If -httproot is non-empty, exposed endpoint (-addr) doubles as https server,
serving static content from that directory. Put index.html file there to
automatically serve it as index document available upon site root (/) request.

Currenly Let's Encrypt (https://letsencrypt.org) is used as an ACME provider.
`
