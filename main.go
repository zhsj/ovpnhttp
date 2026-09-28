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

	"github.com/bclswl0827/govpn/protocols/openvpn"
	"github.com/jessevdk/go-flags"

	"github.com/zhsj/ovpnhttp/internal/proxy"
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

			waitErr := session.Wait(ctx)
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
				Addr         []netip.Prefix
				NumGoroutine int
			}{
				NumGoroutine: runtime.NumGoroutine(),
			}, nil
		},
	}
	proxier.Serve(ctx, ln)
}
