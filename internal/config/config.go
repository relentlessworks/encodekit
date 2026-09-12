package config

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"os"
)

// Config holds all service configuration.
type Config struct {
	Addr   string
	Secret string
}

// Load reads configuration from defaults < env < flags.
func Load() *Config {
	c := &Config{
		Addr:   ":7700",
		Secret: "",
	}

	// Env
	if v := os.Getenv("ENCODEKIT_ADDR"); v != "" {
		c.Addr = v
	}
	if v := os.Getenv("ENCODEKIT_SECRET"); v != "" {
		c.Secret = v
	}

	// Flags
	flag.StringVar(&c.Addr, "addr", c.Addr, "listen address")
	flag.StringVar(&c.Secret, "secret", c.Secret, "token signing secret (auto-generated if empty)")
	flag.Parse()

	// Auto-generate secret if not provided
	if c.Secret == "" {
		b := make([]byte, 32)
		rand.Read(b)
		c.Secret = hex.EncodeToString(b)
	}

	return c
}
