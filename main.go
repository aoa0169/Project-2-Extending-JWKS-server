package main

import (
	"log"
	"net/http"

	"jwks-server/internal/keys"
	"jwks-server/internal/server"
)

func main() {
	store, err := keys.NewStore("totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatalf("failed to initialize key store: %v", err)
	}
	defer store.Close()

	srv := server.New(store)

	mux := http.NewServeMux()

	mux.HandleFunc("/auth", srv.HandleAuth)
	mux.HandleFunc("/auth/", srv.HandleAuth)

	mux.HandleFunc("/.well-known/jwks.json", srv.HandleJWKS)

	log.Println("JWKS server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
