// Command tlstun implements basic VPN over TLS (both client and server).
//
// Client part is expected to be run locally and used by local services as
// a socks5 proxy. Client establishes TLS session to the server running on some
// remote host that performs outgoing requests on behalf of requests made to the
// client. Communication between client and server is multiplexed over a single
// TLS session thus reducing TLS handshake overhead.
//
// Client and server authenticate each other with certificates which can be
// created with openssl or https://github.com/artyom/gencert
//
// Usage example
//
// Generate server and client side certificates, they should be signed by the
// same CA and saved using PEM encoding into a single file with certificate
// followed by CA. Certificate keys should also be saved as a separate
// PEM-encoded files. With gencert tool from https://github.com/artyom/gencert
// this can be done as:
//
// 	gencert -hosts my.domain.tld
//
// This produces four files in the current directory: client certificate + key
// pair and another pair for the server. Note that my.domain.tld should point to
// the host you plan running server part of tlstun.
//
// Now configure tlstun to run on the server that could be reached at
// my.domain.tld like this:
//
// 	tlstun -addr=:9000 -cert=server-cert.pem -key=server-key.pem
//
// The client part is expected to be running locally (on a laptop/workstation,
// etc.):
//
//	tlstun -addr=127.0.0.1:1080 -remote=my.domain.tld:9000 \
//		-cert=client-cert.pem -key=client-key.pem
//
// The presence of -remote flag configures tlstun to run in client mode. It is
// now listening on localhost port 1080 and local software can be configured to
// use this endpoint as a socks5 proxy.
//
// Note that -remote flag can be optionally set multiple times, then client
// probes all servers and picks the one that replied first.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	socks5 "github.com/armon/go-socks5"
	"github.com/artyom/autoflags"
	"github.com/artyom/logger"
	"github.com/artyom/ping"
	"github.com/xtaci/smux"
	"golang.org/x/sync/errgroup"
)

func main() {
	args := struct {
		Addr    string      `flag:"addr,host:port to listen"`
		Cert    string      `flag:"cert,PEM-encoded certificate + CA"`
		Key     string      `flag:"key,PEM-encoded certificate key"`
		Remotes stringSlice `flag:"remote,remote server(s) to connect (setting this enables client mode)"`
	}{}
	autoflags.Parse(&args)
	if args.Cert == "" || args.Key == "" || args.Addr == "" {
		flag.Usage()
		os.Exit(1)
	}
	for _, remote := range args.Remotes {
		if args.Addr == remote {
			fmt.Fprintln(os.Stderr, "-addr and -remote cannot be the same")
			os.Exit(1)
		}
	}
	log := log.New(os.Stderr, "", 0)
	var err error
	switch len(args.Remotes) {
	case 0:
		err = runServer(args.Addr, args.Cert, args.Key, log)
	default:
		err = runClient(args.Addr, args.Cert, args.Key, args.Remotes, log)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runServer(addr, certFile, keyFile string, l logger.Interface) error {
	cfg, err := tlsConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	server, err := socks5.New(&socks5.Config{
		Dial: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 3 * time.Minute,
		}).DialContext,
		Logger: log.New(ioutil.Discard, "", 0),
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	tln := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, cfg)
	smuxCfg := &smux.Config{
		KeepAliveInterval: 45 * time.Second,
		KeepAliveTimeout:  90 * time.Second,
		MaxFrameSize:      4096,
		MaxReceiveBuffer:  4194304,
	}
	for {
		conn, err := tln.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) error {
			start := time.Now()
			defer conn.Close()
			conn.SetDeadline(start.Add(10 * time.Second))
			if err := conn.(*tls.Conn).Handshake(); err != nil {
				return err
			}
			conn.SetDeadline(time.Time{})
			l.Println("connection from", conn.RemoteAddr(), "established")
			defer func() {
				l.Println("connection from", conn.RemoteAddr(), "closed after",
					time.Since(start).Round(time.Second))
			}()
			sess, err := smux.Server(conn, smuxCfg)
			if err != nil {
				return err
			}
			defer sess.Close()
			for {
				stream, err := sess.AcceptStream()
				if err != nil {
					return err
				}
				go server.ServeConn(stream)
			}
		}(conn)
	}
}

func runClient(addr, certFile, keyFile string, remotes []string, log logger.Interface) error {
	for _, remote := range remotes {
		host, port, err := net.SplitHostPort(remote)
		if err != nil {
			return err
		}
		if host == "" || port == "" {
			return fmt.Errorf("-remote=%q is not valid", remote)
		}
	}
	cfg, err := tlsConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	dialFunc := func(remote string) (net.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 3 * time.Minute,
		}, "tcp", remote, cfg)
	}
	pool := &connPool{dialFunc: dialFunc, log: log, addrs: remotes, smuxCfg: &smux.Config{
		KeepAliveInterval: 45 * time.Second,
		KeepAliveTimeout:  90 * time.Second,
		MaxFrameSize:      4096,
		MaxReceiveBuffer:  4194304,
	}}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer pool.runPing()()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) error {
			defer conn.Close()
			rconn, err := pool.dial()
			if err != nil {
				return err
			}
			defer rconn.Close()
			go func() { defer conn.Close(); io.Copy(rconn, conn) }()
			_, err = io.Copy(conn, rconn)
			return err
		}(conn)
	}
}

type connPool struct {
	dialFunc func(addr string) (net.Conn, error)
	smuxCfg  *smux.Config
	log      logger.Interface

	mu     sync.Mutex
	sess   *smux.Session
	reused int      // number of times session was reused
	sorted bool     // whether addrs are sorted in "best route" order
	addrs  []string // has at least 1 element
}

func (p *connPool) runPing() (cancel func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.addrs) <= 1 {
		return func() {}
	}
	addrs := make([]string, len(p.addrs))
	copy(addrs, p.addrs)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		var initDone bool
		for {
			switch {
			case initDone:
				select {
				case <-ticker.C:
				case <-ctx.Done():
					return
				}
			default:
				select {
				default:
					initDone = true
				case <-ctx.Done():
					return
				}
			}
			g, ctx := errgroup.WithContext(ctx)
			res := make([]ping.Summary, len(addrs))
			for i, addr := range addrs {
				i, addr := i, addr // shadow
				g.Go(func() error {
					host, _, err := net.SplitHostPort(addr)
					if err != nil {
						return err
					}
					s, err := pingAddress(ctx, host, 10)
					if err == nil {
						res[i] = s
					}
					return err
				})
			}
			if err := g.Wait(); err != nil {
				p.log.Println("ping:", err)
				p.mu.Lock()
				p.sorted = false
				p.mu.Unlock()
				continue
			}
			sort.Sort(&addrSorter{addrs: addrs, res: res})
			p.mu.Lock()
			p.sorted = true
			copy(p.addrs, addrs)
			p.mu.Unlock()
			p.log.Printf("best ping endpoint: %s (lost:%d/%d, rtt:%v)", addrs[0],
				res[0].Lost, res[0].Sent, res[0].AvgRTT.Truncate(time.Millisecond))
		}
	}()
	return cancel
}

func (p *connPool) dial() (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var retry bool
tryAgain:
	if p.sess == nil {
		var sess *smux.Session
		var err error
		switch {
		case p.sorted:
			sess, err = newSession(p.dialFunc, p.smuxCfg, p.addrs)
		default:
			sess, err = newSessionMulti(p.dialFunc, p.smuxCfg, p.addrs)
		}
		if err != nil {
			return nil, err
		}
		p.sess, p.reused = sess, 0
	}
	if p.reused > 100 {
		switch n := p.sess.NumStreams(); {
		case n == 0:
			p.sess.Close()
			p.sess, p.reused = nil, 0
			goto tryAgain
		case n < 50:
			go func(sess *smux.Session) {
				ticker := time.NewTicker(time.Minute)
				defer ticker.Stop()
				for range ticker.C {
					if sess.NumStreams() == 0 {
						sess.Close()
						return
					}
				}
			}(p.sess)
			p.sess, p.reused = nil, 0
			goto tryAgain
		}
	}
	if p.sess.IsClosed() {
		p.sess.Close()
		p.sess, p.reused = nil, 0
		if !retry {
			retry = true
			goto tryAgain
		}
		return nil, fmt.Errorf("session is closed")
	}
	p.reused++
	return p.sess.OpenStream()
}

// newSession dials addresses from addrs sequentially until it succeeds
// establishing new smux.Session, returning the first that succeeds right away.
// If no session was established, the last error is returned.
func newSession(dialFunc func(string) (net.Conn, error), cfg *smux.Config, addrs []string) (*smux.Session, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no destinations to dial")
	}
	var errOut error
	for _, addr := range addrs {
		conn, err := dialFunc(addr)
		if err != nil {
			errOut = err
			continue
		}
		sess, err := smux.Client(conn, cfg)
		if err != nil {
			conn.Close()
			errOut = err
			continue
		}
		return sess, nil
	}
	return nil, errOut
}

// newSessionMulti dials multiple addresses in parallel and tries to establish a new
// smux.Session on each, returning the first that succeeds right away. Other
// successfully established sessions are closed as unused. If no session was
// established, the last error is returned.
func newSessionMulti(dialFunc func(string) (net.Conn, error), cfg *smux.Config, addrs []string) (*smux.Session, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no destinations to dial")
	}
	sessCh := make(chan *smux.Session)
	errCh := make(chan error)
	for _, addr := range addrs {
		go func(addr string) {
			sess, err := func() (*smux.Session, error) {
				conn, err := dialFunc(addr)
				if err != nil {
					return nil, err
				}
				sess, err := smux.Client(conn, cfg)
				if err != nil {
					conn.Close()
					return nil, err
				}
				return sess, nil
			}()
			if err != nil {
				errCh <- err
				return
			}
			select {
			case sessCh <- sess:
			default:
				sess.Close() // don't leak unused connection
			}
		}(addr)
	}
	var err error
	for i := 0; i < len(addrs); i++ {
		select {
		case sess := <-sessCh:
			return sess, nil
		case err = <-errCh:
		}
	}
	return nil, err
}

func tlsConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) != 2 {
		return nil, fmt.Errorf("certificate should have 2 concatenated certificates: server + CA")
	}
	ca, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(ca)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs:      certPool,
		ClientCAs:    certPool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		ClientSessionCache:       tls.NewLRUClientSessionCache(0),
	}, nil
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

// implements flag.Value interface
type stringSlice []string

func (c *stringSlice) String() string { return fmt.Sprint(*c) }
func (c *stringSlice) Set(value string) error {
	*c = append(*c, value)
	return nil
}

func pingAddress(ctx context.Context, addr string, count int) (ping.Summary, error) {
	p, err := ping.NewICMP(addr)
	if err != nil {
		return ping.Summary{}, err
	}
	defer p.Close()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
pingLoop:
	for i := 0; ; i++ {
		if count > 0 && i == count {
			break
		}
		switch i {
		case 0:
		default:
			select {
			case <-ctx.Done():
				break pingLoop
			case <-ticker.C:
			}
		}
		if _, _, err := p.Ping(); err != nil {
			return ping.Summary{}, err
		}
	}
	return p.Stat(), nil
}

// addrSorter implements sort.Interface to allow for simultaneous sort of two
// corresponding slices: addresses and their ping results
type addrSorter struct {
	addrs []string
	res   []ping.Summary
}

func (s *addrSorter) Len() int { return len(s.addrs) }

func (s *addrSorter) Swap(i, j int) {
	s.addrs[i], s.addrs[j] = s.addrs[j], s.addrs[i]
	s.res[i], s.res[j] = s.res[j], s.res[i]
}

func (s *addrSorter) Less(i, j int) bool {
	ri, rj := s.res[i], s.res[j]
	if ri.Sent != rj.Sent {
		return ri.Sent > rj.Sent
	}
	if ri.Lost != rj.Lost {
		return ri.Lost < rj.Lost
	}
	return ri.AvgRTT < rj.AvgRTT
}
