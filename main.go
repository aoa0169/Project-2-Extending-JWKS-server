package main

import (
	"bufio"
	"log"
	"net/http"
	"os"
	"strings"

	"jwks-server/internal/keys"
	"jwks-server/internal/server"
)

func loadDotEnv(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if key != "" && os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
	}
}

func main() {
	loadDotEnv(".env")

	store, err := keys.NewStore("totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatalf("failed to initialize key store: %v", err)
	}
	defer store.Close()

	srv := server.New(store)

	mux := http.NewServeMux()

	mux.HandleFunc("/auth", srv.HandleAuth)
	mux.HandleFunc("/auth/", srv.HandleAuth)
	mux.HandleFunc("/register", srv.HandleRegister)

	mux.HandleFunc("/.well-known/jwks.json", srv.HandleJWKS)

	log.Println("JWKS server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

