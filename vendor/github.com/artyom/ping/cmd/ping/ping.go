// Command ping is an example of using github.com/artyom/ping package. It
// implements basic utility akin to ping(8) command.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/artyom/ping"
)

func main() {
	var count int
	flag.IntVar(&count, "c", 0, "number of packets to send, 0 for indefinite")
	flag.Parse()
	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		<-sigCh
		cancel()
	}()
	if _, err := ICMP(ctx, os.Stdout, count, flag.Args()[0]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ping [flags] addr")
		flag.PrintDefaults()
	}
}

// ICMP pings addr using IPv4 ICMP echo messages until count packets are sent or
// ctx is canceled. If w is not null, output similar to ping(8) command is
// written there. If count is not positive, function runs until ctx is canceled.
// If addr is not an IPv4 address, it is resolved and first IPv4 record is used.
func ICMP(ctx context.Context, w io.Writer, count int, addr string) (*ping.Summary, error) {
	p, err := ping.NewICMP(addr)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	peerIP := p.PeerIP()
	fmt.Fprintf(w, "PING %s (%s): 56 data bytes\n", addr, peerIP)
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
		ok, info, err := p.Ping()
		if err != nil {
			return nil, err
		}
		switch {
		case ok:
			fmt.Fprintf(w, "%d bytes from %s: icmp_seq=%d ttl=%d time=%v\n", info.Size, peerIP,
				i, info.TTL, info.RTT.Truncate(time.Microsecond))
		default:
			fmt.Fprintln(w, "Request timeout for icmp_seq", i)
		}
	}
	summary := p.Stat()
	fmt.Fprintf(w, "\n--- %s ping statistics ---\n", addr)
	fmt.Fprintln(w, prettyStat(summary))
	return &summary, nil
}

func prettyStat(s ping.Summary) string {
	var pct float64
	if s.Sent > 0 && s.Lost > 0 {
		pct = float64(s.Lost) / float64(s.Sent) * 100
	}
	return fmt.Sprintf("%d packets transmitted, %d packets received, %.1f%% packet loss\n"+
		"round-trip min/avg/max/stddev = %v/%v/%v/%v", s.Sent, s.Sent-s.Lost, pct,
		s.MinRTT.Truncate(time.Microsecond),
		s.AvgRTT.Truncate(time.Microsecond),
		s.MaxRTT.Truncate(time.Microsecond),
		s.DevRTT.Truncate(time.Microsecond),
	)
}
