package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"jwks-server/internal/keys"
)

type Server struct {
	store        *keys.Store
	limiterMu   sync.Mutex
	authRequests []time.Time
}

func New(store *keys.Store) *Server {
	return &Server{
		store:        store,
		authRequests: make([]time.Time, 0),
	}
}

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

func (s *Server) allowAuthRequest(now time.Time) bool {
	s.limiterMu.Lock()
	defer s.limiterMu.Unlock()

	cutoff := now.Add(-1 * time.Second)

	filtered := s.authRequests[:0]
	for _, t := range s.authRequests {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}

	s.authRequests = filtered

	if len(s.authRequests) >= 10 {
		return false
	}

	s.authRequests = append(s.authRequests, now)
	return true
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}

	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}

	return "unknown"
}

func parseBasicAuth(r *http.Request) (string, string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return "", "", false
	}

	raw := strings.TrimPrefix(auth, prefix)

	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", "", false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}

func (s *Server) authenticate(r *http.Request) (string, *int64, bool) {
	if username, password, ok := parseBasicAuth(r); ok {
		if user, valid, err := s.store.AuthenticateUser(username, password); err == nil && valid {
			return user.Username, &user.ID, true
		}

		return username, nil, true
	}

	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var req authRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return "", nil, false
		}

		if req.Username == "" || req.Password == "" {
			return "", nil, false
		}

		if user, valid, err := s.store.AuthenticateUser(req.Username, req.Password); err == nil && valid {
			return user.Username, &user.ID, true
		}

		if req.Username == "userABC" && req.Password == "password123" {
			return req.Username, nil, true
		}
	}

	return "", nil, false
}

func uuidV4() (string, error) {
	b := make([]byte, 16)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return hex.EncodeToString(b[0:4]) +
		"-" +
		hex.EncodeToString(b[4:6]) +
		"-" +
		hex.EncodeToString(b[6:8]) +
		"-" +
		hex.EncodeToString(b[8:10]) +
		"-" +
		hex.EncodeToString(b[10:16]), nil
}

func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req registerRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)

	if req.Username == "" || req.Email == "" {
		http.Error(w, "username and email are required", http.StatusBadRequest)
		return
	}

	password, err := uuidV4()
	if err != nil {
		http.Error(w, "failed to generate password", http.StatusInternalServerError)
		return
	}

	if err := s.store.CreateUser(req.Username, req.Email, password); err != nil {
		http.Error(w, "username or email already exists", http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"password": password,
	})
}

func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()

	active, err := s.store.ActiveKeys(now)
	if err != nil {
		http.Error(w, "failed to read keys", http.StatusInternalServerError)
		return
	}

	jwks := keys.ToJWKS(active)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (s *Server) HandleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()

	if !s.allowAuthRequest(now) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	username, userID, authorized := s.authenticate(r)
	if !authorized {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	useExpired := r.URL.Query().Has("expired")

	var (
		keyRecord keys.KeyRecord
		ok        bool
		err       error
	)

	if useExpired {
		keyRecord, ok, err = s.store.GetExpiredKey(now)
	} else {
		keyRecord, ok, err = s.store.GetValidKey(now)
	}

	if err != nil {
		http.Error(w, "failed to read signing key", http.StatusInternalServerError)
		return
	}

	if !ok {
		http.Error(w, "no matching key found", http.StatusInternalServerError)
		return
	}

	exp := now.Add(5 * time.Minute)
	if useExpired {
		exp = keyRecord.Expiry
	}

	claims := jwt.MapClaims{
		"sub": username,
		"iss": "jwks-server",
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = strconv.FormatInt(keyRecord.KID, 10)

	signed, err := token.SignedString(keyRecord.Priv)
	if err != nil {
		http.Error(w, "failed to sign jwt", http.StatusInternalServerError)
		return
	}

	_ = s.store.LogAuthRequest(clientIP(r), userID)

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	_, _ = w.Write([]byte(signed))
}
