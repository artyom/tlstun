// Package ping provides primitives to ping network endpoints.
package ping

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Summary holds statistics from a single ping run
type Summary struct {
	Sent, Lost int
	MinRTT     time.Duration
	AvgRTT     time.Duration
	MaxRTT     time.Duration
	DevRTT     time.Duration
}

// RoundInfo holds result of a single ping request/reply exchange
type RoundInfo struct {
	RTT  time.Duration
	TTL  int
	Size int
}

// Pinger is used to ping remote endpoints.
type Pinger interface {
	// Ping sends single packet and waits for a limited time for reply.
	// Returned values are whether reply was received in time, measured
	// round trip time, number of bytes in received payload and error. It
	// only returns errors on non-recoverable errors, if it does not receive
	// reply for implementation-specific time limit, it reports false with
	// nil error which should be interpreted as timeout.
	Ping() (ok bool, info RoundInfo, err error)

	// PeerIP returns IP address Ping sends packets to
	PeerIP() net.IP

	// Summary returns statistics collected from multiple Ping calls. It is
	// usually called after multiple Ping calls and followed by Close call.
	Stat() Summary

	// Close frees resources used by Pinger (network sockets, etc.) Other
	// methods should not be called after Close.
	Close() error
}

type icmpPinger struct {
	mu sync.Mutex
	Summary
	udpAddr *net.UDPAddr
	conn    *icmp.PacketConn
	msgID   int // ping session id
	seq     int // sequence number

	m, s, k int64 // for stddev calculations

	rttSum time.Duration
	rcvBuf []byte
	sndBuf []byte
}

func (p *icmpPinger) PeerIP() net.IP {
	if p.udpAddr != nil {
		return p.udpAddr.IP
	}
	return nil
}

func (p *icmpPinger) Ping() (ok bool, info RoundInfo, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	defer func() { p.seq++ }()
	start := time.Now()
	binary.LittleEndian.PutUint64(p.sndBuf[3:], uint64(start.UnixNano()))
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: p.msgID, Seq: p.seq, Data: p.sndBuf},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false, RoundInfo{}, err
	}
	sendTime := time.Now()
	if err := p.conn.SetWriteDeadline(sendTime.Add(time.Second)); err != nil {
		return false, RoundInfo{}, err
	}
	if _, err := p.conn.WriteTo(b, p.udpAddr); err != nil {
		return false, RoundInfo{}, err
	}
	p.Summary.Sent++
	if err := p.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return false, RoundInfo{}, err
	}

	ipconn := p.conn.IPv4PacketConn()
	for {
		if err := ipconn.SetControlMessage(ipv4.FlagTTL, true); err != nil {
			return false, RoundInfo{}, err
		}
		n, cm, _, err := ipconn.ReadFrom(p.rcvBuf)
		if te, ok := err.(interface{ Timeout() bool }); ok && te.Timeout() {
			p.Summary.Lost++
			return false, RoundInfo{}, nil
		}
		if err != nil {
			return false, RoundInfo{}, err
		}
		rtt := time.Since(sendTime)
		msg2, err := icmp.ParseMessage(1, p.rcvBuf[:n])
		if err != nil {
			continue
		}
		if msg2.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		if body, ok := msg2.Body.(*icmp.Echo); ok &&
			body.ID == p.msgID &&
			body.Seq == p.seq &&
			bytes.Equal(body.Data, p.sndBuf) {
			{
				if p.k == 0 {
					p.k = 1
				}
				val := int64(rtt)
				_m := p.m
				p.m += (val - _m) / p.k
				p.s += (val - _m) * (val - p.m)
				p.k++
			}
			if p.Summary.MaxRTT == 0 || p.Summary.MaxRTT < rtt {
				p.Summary.MaxRTT = rtt
			}
			if p.Summary.MinRTT == 0 || p.Summary.MinRTT > rtt {
				p.Summary.MinRTT = rtt
			}
			p.rttSum += rtt
			p.Summary.AvgRTT = p.rttSum / time.Duration(p.Summary.Sent)
			return true, RoundInfo{RTT: rtt, TTL: cm.TTL, Size: n}, nil
		}
	}
}

func (p *icmpPinger) Close() error { return p.conn.Close() }

func (p *icmpPinger) Stat() Summary {
	p.mu.Lock()
	defer p.mu.Unlock()
	summary := p.Summary
	summary.DevRTT = time.Duration(int64(math.Sqrt(float64(p.s / (p.k - 1)))))
	return summary
}

// NewICMP returns new Pinger which pings addr using IPv4 ICMP echo messages.
// addr should either be an IPv4 or hostname that resolves to IPv4. If addr
// resolves to multiple addresses, the first IPv4 record is used.
//
// Currently this only works on macOS or Linux; if on Linux you get permission
// denied error, ensure that sysctl net.ipv4.ping_group_range includes your
// group id.
func NewICMP(addr string) (Pinger, error) {
	dst := net.ParseIP(addr)
	if dst == nil {
		ips, err := net.LookupIP(addr)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				dst = ip
				break
			}
		}
	}
	if dst == nil {
		return nil, errors.New("cannot resolve address to ipv4")
	}
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	sndBuf := make([]byte, 56)
	_ = append(sndBuf[:0], "ping"...)
	return &icmpPinger{
		udpAddr: &net.UDPAddr{IP: dst},
		conn:    c,
		msgID:   c.LocalAddr().(*net.UDPAddr).Port,
		rcvBuf:  make([]byte, 1500),
		sndBuf:  sndBuf,
	}, nil
}
