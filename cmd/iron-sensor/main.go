package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"iron-sensor/internal/agent"
	"iron-sensor/internal/classifier"
	"iron-sensor/internal/config"
	"iron-sensor/internal/events"
	"iron-sensor/internal/sink"
)

func main() {
	configPath := flag.String("config", "", "Path to YAML config file")
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "error: iron-sensor must run as root (BPF requires CAP_BPF/CAP_SYS_ADMIN)")
		os.Exit(1)
	}

	var cfg config.Config
	if *configPath != "" {
		var err error
		cfg, err = config.Load(*configPath)
		if err != nil {
			log.Fatalf("loading config: %v", err)
		}
	} else {
		cfg = config.Default()
	}

	var s sink.Sink
	switch cfg.SinkType {
	case "stdout":
		s = sink.NewStdoutSink()
	case "file":
		if err := os.MkdirAll(filepath.Dir(cfg.FileSink.OutputPath), 0o755); err != nil {
			log.Fatalf("creating output directory: %v", err)
		}
		s = sink.NewFileSink(cfg.FileSink)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown sink_type %q (use stdout or file)\n", cfg.SinkType)
		os.Exit(1)
	}

	emitter := events.NewEmitter(s, cfg.Rules.MinSeverity)
	defer emitter.Close()

	cls := classifier.New(cfg.Rules.Overrides)
	sigs := agent.BuildSignatures(cfg.Detections.Binaries)
	tracker := agent.NewTracker(emitter, cls, sigs)

	log.Printf("iron-sensor %s starting (sink=%s)", events.SensorVersion, cfg.SinkType)

	if err := tracker.Load(); err != nil {
		log.Fatalf("loading BPF programs: %v", err)
	}
	defer tracker.Close()

	if err := tracker.Bootstrap(); err != nil {
		log.Fatalf("bootstrap scan: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := tracker.Run(ctx); err != nil {
		log.Fatalf("run: %v", err)
	}

	log.Println("iron-sensor stopped")
}
