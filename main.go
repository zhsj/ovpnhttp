package main

import (
	"context"
	"encoding/hex"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"

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

	session, err := openvpn.NewClient(openvpn.Config{
		Remote: opts.Server, Port: opts.Port, PeerFingerprints: [][]byte{peerFP},
		Username: opts.Username, Password: opts.Passwd,
		Logger: logger,
	}).Start(ctx)
	if err != nil {
		logger.Fatal(err)
	}
	defer session.Close()

	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		logger.Fatal(err)
	}

	proxier := proxy.Proxy{
		Logger: logger,
		Dial:   session.DialContext,
		DNS:    opts.DNS,
		Stats: func() (any, error) {
			return struct {
				Addr         []netip.Prefix
				NumGoroutine int
			}{
				Addr:         session.Addresses(),
				NumGoroutine: runtime.NumGoroutine(),
			}, nil
		},
	}
	proxier.Serve(ctx, ln)
}
