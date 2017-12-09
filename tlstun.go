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
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	socks5 "github.com/armon/go-socks5"
	"github.com/artyom/autoflags"
	"github.com/artyom/logger"
	"github.com/xtaci/smux"
)

func main() {
	args := struct {
		Addr   string `flag:"addr,host:port to listen"`
		Cert   string `flag:"cert,PEM-encoded certificate + CA"`
		Key    string `flag:"key,PEM-encoded certificate key"`
		Remote string `flag:"remote,remote server to connect (setting this enables client mode)"`
	}{}
	autoflags.Parse(&args)
	if args.Cert == "" || args.Key == "" || args.Addr == "" {
		flag.Usage()
		os.Exit(1)
	}
	if args.Addr == args.Remote {
		fmt.Fprintln(os.Stderr, "-addr and -remote cannot be the same")
		os.Exit(1)
	}
	log := log.New(os.Stderr, "", 0)
	var err error
	switch args.Remote {
	case "":
		err = runServer(args.Addr, args.Cert, args.Key, log)
	default:
		err = runClient(args.Addr, args.Remote, args.Cert, args.Key, log)
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

func runClient(addr, remote, certFile, keyFile string, log logger.Interface) error {
	if _, _, err := net.SplitHostPort(remote); err != nil {
		return err
	}
	cfg, err := tlsConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	dialFunc := func() (net.Conn, error) {
		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 3 * time.Minute,
		}, "tcp", remote, cfg)
		if err == nil {
			log.Println("established new connection to", conn.RemoteAddr())
		}
		return conn, err
	}
	pool := &connPool{dialFunc: dialFunc, smuxCfg: &smux.Config{
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
	dialFunc func() (net.Conn, error)
	smuxCfg  *smux.Config

	mu   sync.Mutex
	sess *smux.Session
}

func (p *connPool) dial() (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var retry bool
tryAgain:
	if p.sess == nil {
		conn, err := p.dialFunc()
		if err != nil {
			return nil, err
		}
		sess, err := smux.Client(conn, p.smuxCfg)
		if err != nil {
			conn.Close()
			return nil, err
		}
		p.sess = sess
	}
	if p.sess.IsClosed() {
		p.sess.Close()
		p.sess = nil
		if !retry {
			retry = true
			goto tryAgain
		}
		return nil, fmt.Errorf("session is closed")
	}
	return p.sess.OpenStream()
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
