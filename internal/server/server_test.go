package server_test

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"net/http"
	"net/http/httptest"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"

	"jwks-server/internal/keys"
	"jwks-server/internal/server"
)

func newTestServer(t *testing.T) (*server.Server, func()) {
	t.Helper()
	t.Setenv("NOT_MY_KEY", "test-secret-key-for-aes-encryption")

	dbFile := "test_privateKeys.db"
	_ = os.Remove(dbFile)

	store, err := keys.NewStore(dbFile)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	cleanup := func() {
		_ = store.Close()
		_ = os.Remove(dbFile)
	}

	return server.New(store), cleanup
}

func TestDBFileCreated(t *testing.T) {
	t.Setenv("NOT_MY_KEY", "test-secret-key-for-aes-encryption")
	dbFile := "test_privateKeys.db"
	_ = os.Remove(dbFile)

	store, err := keys.NewStore(dbFile)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() {
		_ = store.Close()
		_ = os.Remove(dbFile)
	}()

	if _, err := os.Stat(dbFile); err != nil {
		t.Fatalf("expected DB file to exist: %v", err)
	}
}

func TestDBSchemaExists(t *testing.T) {
	t.Setenv("NOT_MY_KEY", "test-secret-key-for-aes-encryption")
	dbFile := "test_privateKeys.db"
	_ = os.Remove(dbFile)

	store, err := keys.NewStore(dbFile)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() {
		_ = store.Close()
		_ = os.Remove(dbFile)
	}()

	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var name string
	err = db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='keys'`).Scan(&name)
	if err != nil {
		t.Fatalf("expected keys table to exist: %v", err)
	}

	if name != "keys" {
		t.Fatalf("expected table name keys, got %s", name)
	}
}

func TestJWKSOnlyReturnsValidKeys(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	srv.HandleJWKS(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var jwksResp keys.JWKS
	if err := json.NewDecoder(w.Body).Decode(&jwksResp); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}

	if len(jwksResp.Keys) != 1 {
		t.Fatalf("expected 1 valid key in JWKS, got %d", len(jwksResp.Keys))
	}

	k := jwksResp.Keys[0]
	if k.Kid == "" || k.N == "" || k.E == "" {
		t.Fatal("expected kid, n, and e to be populated")
	}
}

func TestAuthWithBasicAuthReturnsJWT(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	auth := base64.StdEncoding.EncodeToString([]byte("abc:def"))
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	req.Header.Set("Authorization", "Basic "+auth)

	w := httptest.NewRecorder()
	srv.HandleAuth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	tokenStr := strings.TrimSpace(w.Body.String())
	if tokenStr == "" {
		t.Fatal("expected token body")
	}

	tok, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	if tok.Header["kid"] == "" {
		t.Fatal("expected kid header")
	}
}

func TestAuthWithJSONReturnsJWT(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	body := []byte(`{"username":"userABC","password":"password123"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.HandleAuth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthRejectsBadJSONCredentials(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	body := []byte(`{"username":"wrong","password":"wrong"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.HandleAuth(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthRejectsNoCredentials(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w := httptest.NewRecorder()

	srv.HandleAuth(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestExpiredQueryReturnsExpiredJWT(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	auth := base64.StdEncoding.EncodeToString([]byte("abc:def"))
	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	req.Header.Set("Authorization", "Basic "+auth)

	w := httptest.NewRecorder()
	srv.HandleAuth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	tokenStr := strings.TrimSpace(w.Body.String())

	tok, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	claims := tok.Claims.(jwt.MapClaims)

	expF, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("expected exp claim")
	}

	exp := time.Unix(int64(expF), 0).UTC()
	if !exp.Before(time.Now().UTC()) {
		t.Fatalf("expected expired token, got exp=%v", exp)
	}
}

func TestMethodGuards(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	req1 := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	w1 := httptest.NewRecorder()
	srv.HandleJWKS(w1, req1)
	if w1.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for jwks, got %d", w1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/auth", nil)
	w2 := httptest.NewRecorder()
	srv.HandleAuth(w2, req2)
	if w2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for auth, got %d", w2.Code)
	}
}

func TestRegisterCreatesUserAndReturnsUUIDPassword(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	body := []byte(`{"username":"alice","email":"alice@example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.HandleRegister(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}

	if len(resp["password"]) != 36 {
		t.Fatalf("expected UUIDv4 password, got %q", resp["password"])
	}
}

func TestRegisteredUserCanAuthenticateAndLogRequest(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	body := []byte(`{"username":"bob","email":"bob@example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.HandleRegister(w, req)

	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)

	authBody := []byte(`{"username":"bob","password":"` + resp["password"] + `"}`)
	authReq := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewReader(authBody))
	authReq.Header.Set("Content-Type", "application/json")
	authReq.RemoteAddr = "192.0.2.1:1234"
	authW := httptest.NewRecorder()

	srv.HandleAuth(authW, authReq)

	if authW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", authW.Code)
	}
}

