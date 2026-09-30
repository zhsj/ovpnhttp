package main

import (
	"context"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/protocols/openvpn"
	"github.com/jessevdk/go-flags"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/zhsj/ovpnhttp/internal/proxy"
)

const (
	pingInterval    = 3 * time.Second
	pingTimeout     = 2 * time.Second
	pingMaxFailures = 5
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	opts := struct {
		Server   string `long:"server" env:"SERVER" required:"true"`
		Port     int    `long:"port" env:"PORT" default:"1194"`
		PeerFP   string `long:"peer-fp" env:"PEER_FP" required:"true"`
		DNS      string `long:"dns" env:"DNS" default:"https://1.0.0.1"`
		Listen   string `long:"listen" env:"LISTEN" default:"localhost:1080"`
		Username string `long:"username" env:"USERNAME" required:"true"`
		Passwd   string `long:"password" env:"PASSWORD" required:"true"`
	}{}

	parser := flags.NewParser(&opts, flags.Default)
	if _, err := parser.Parse(); err != nil {
		os.Exit(1)
	}

	peerFP, err := hex.DecodeString(opts.PeerFP)
	if err != nil {
		logger.Fatal(err)
	}

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)

	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		logger.Fatal(err)
	}

	var (
		dialMu sync.RWMutex
		dialFn = func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("vpn session not established")
		}
	)

	go func() {
		for {
			session, err := openvpn.NewClient(openvpn.Config{
				Remote: opts.Server, Port: opts.Port, PeerFingerprints: [][]byte{peerFP},
				Username: opts.Username, Password: opts.Passwd,
				Logger: logger,
			}).Start(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Printf("Failed to start VPN session: %v, retrying in 5s...", err)
				time.Sleep(5 * time.Second)
				continue
			}

			logger.Printf("VPN session established")

			dialMu.Lock()
			dialFn = session.DialContext
			dialMu.Unlock()

			pingCtx, cancelPing := context.WithCancel(ctx)
			go monitorGateway(pingCtx, session, logger)

			waitErr := session.Wait(ctx)
			cancelPing()

			logger.Printf("VPN session ended: %v, reconnecting...", waitErr)

			dialMu.Lock()
			dialFn = func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("vpn session reconnecting")
			}
			dialMu.Unlock()

			session.Close()

			if ctx.Err() != nil {
				return
			}

			time.Sleep(1 * time.Second)
		}
	}()

	proxier := proxy.Proxy{
		Logger: logger,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialMu.RLock()
			defer dialMu.RUnlock()
			return dialFn(ctx, network, address)
		},
		DNS: opts.DNS,
		Stats: func() (any, error) {
			return struct {
				NumGoroutine int
			}{
				NumGoroutine: runtime.NumGoroutine(),
			}, nil
		},
	}
	proxier.Serve(ctx, ln)
}

func monitorGateway(ctx context.Context, session *govpn.Session, logger *log.Logger) {
	var gateway string
	for _, addr := range session.Addresses() {
		if addr.Addr().Is4() {
			ip := addr.Masked().Addr().As4()
			ip[3]++
			gateway = netip.AddrFrom4(ip).String()
			break
		}
	}
	if gateway == "" {
		return
	}

	logger.Printf("ping: monitoring gateway %s", gateway)

	var failures int
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if ping(ctx, session, gateway) {
			failures = 0
			continue
		}
		failures++
		logger.Printf("ping: timeout to %s (%d/%d)", gateway, failures, pingMaxFailures)
		if failures >= pingMaxFailures {
			logger.Printf("ping: %d consecutive timeouts, closing session to reconnect", pingMaxFailures)
			_ = session.Close()
			return
		}
	}
}

func ping(ctx context.Context, session *govpn.Session, gateway string) bool {
	conn, err := session.DialICMP4Context(ctx, gateway)
	if err != nil {
		return false
	}
	defer conn.Close()

	b, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("ping")},
	}).Marshal(nil)
	if err != nil {
		return false
	}
	if _, err := conn.Write(b); err != nil {
		return false
	}
	conn.SetReadDeadline(time.Now().Add(pingTimeout))

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	rm, err := icmp.ParseMessage(1, buf[:n])
	return err == nil && rm.Type == ipv4.ICMPTypeEchoReply
}
