package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SinkType   string           `yaml:"sink_type"`
	FileSink   FileSinkConfig   `yaml:"file_sink"`
	Rules      RulesConfig      `yaml:"rules"`
	Detections DetectionsConfig `yaml:"detections"`
}

type DetectionsConfig struct {
	Binaries []BinaryDetection `yaml:"binaries"`
}

type BinaryDetection struct {
	Name    string `yaml:"name"`
	Binary  string `yaml:"binary"`
}

type FileSinkConfig struct {
	OutputPath string `yaml:"output_path"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	Compress   bool   `yaml:"compress"`
}

type RulesConfig struct {
	MinSeverity *int                    `yaml:"min_severity"`
	Overrides   map[string]RuleOverride `yaml:"overrides"`
}

type RuleOverride struct {
	Severity *int  `yaml:"severity"`
	Enabled  *bool `yaml:"enabled"`
}

func Default() Config {
	return Config{
		SinkType: "file",
		FileSink: FileSinkConfig{
			OutputPath: "/var/log/iron/sensor/events.json",
			MaxSize:    100,
			MaxBackups: 5,
			Compress:   true,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}
