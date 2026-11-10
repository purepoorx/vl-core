// Command vl-core is a minimal, standalone VLESS client/server.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/purepoorx/vl-core/core"
	"github.com/purepoorx/vl-core/protocol"
)

const version = "0.1.3"

type service interface {
	Serve() error
	Close() error
}

func main() {
	var (
		configPath = flag.String("c", "config.json", "path to JSON configuration file")
		role       = flag.String("role", "", "override role from config: server | client")
		listen     = flag.String("listen", "", "override listen address")
		logLevel   = flag.String("log", "", "override log level: debug | info | warn | error")
		genUUID    = flag.Bool("gen-uuid", false, "print a random UUID and exit")
		showVer    = flag.Bool("v", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("vl-core %s\n", version)
		return
	}
	if *genUUID {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		id[6] = (id[6] & 0x0f) | 0x40 // UUID v4
		id[8] = (id[8] & 0x3f) | 0x80 // RFC 4122 variant
		fmt.Println(protocol.UUID(id).String())
		return
	}

	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}
	if *role != "" {
		cfg.Role = *role
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	log := core.NewLogger(cfg.LogLevel, os.Stderr)
	var svc service
	switch cfg.Role {
	case "server":
		svc, err = core.NewServer(cfg, log)
	case "client":
		svc, err = core.NewClient(cfg, log)
	}
	if err != nil {
		log.Error("init failed: %v", err)
		os.Exit(1)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- svc.Serve() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil {
			log.Error("serve failed: %v", err)
			os.Exit(1)
		}
	case <-sigCh:
		log.Info("shutting down")
		_ = svc.Close()
	}
}
