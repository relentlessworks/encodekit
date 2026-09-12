package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/relentlessworks/encodekit/internal/api"
	"github.com/relentlessworks/encodekit/internal/auth"
	"github.com/relentlessworks/encodekit/internal/config"
	"github.com/relentlessworks/encodekit/internal/store"
)

func main() {
	cfg := config.Load()

	dataFile := os.Getenv("ENCODEKIT_DATA")
	if dataFile == "" {
		dataFile = "encodekit-data.json"
	}

	authMgr := auth.New(cfg.Secret)
	dataStore := store.New(dataFile)
	server := api.NewServer(authMgr, dataStore)

	log.Printf("encodekit starting on %s", cfg.Addr)
	fmt.Fprintf(os.Stderr, "encodekit v0.1.0 — listening on %s\n", cfg.Addr)
	fmt.Fprintf(os.Stderr, "GET /help for usage instructions\n")

	if err := http.ListenAndServe(cfg.Addr, server.Routes()); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
