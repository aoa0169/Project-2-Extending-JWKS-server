package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 1
	argonKeyLen  uint32 = 32
	saltLen             = 16
)

type Store struct {
	db *sql.DB
}

type UserRecord struct {
	ID       int64
	Username string
	Email    string
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	store := &Store{db: db}

	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := store.seedIfNeeded(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) init() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS keys(
			kid INTEGER PRIMARY KEY AUTOINCREMENT,
			key BLOB NOT NULL,
			iv BLOB NOT NULL,
			exp INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS users(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			email TEXT UNIQUE,
			date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS auth_logs(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_ip TEXT NOT NULL,
			request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			user_id INTEGER,
			FOREIGN KEY(user_id) REFERENCES users(id)
		);
	`)
	return err
}

func (s *Store) seedIfNeeded() error {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return nil
	}

	now := time.Now().UTC()

	expiredPriv, err := GenerateRSAKey()
	if err != nil {
		return err
	}

	validPriv, err := GenerateRSAKey()
	if err != nil {
		return err
	}

	expiredPEM, err := EncodePrivateKeyToPEM(expiredPriv)
	if err != nil {
		return err
	}

	validPEM, err := EncodePrivateKeyToPEM(validPriv)
	if err != nil {
		return err
	}

	if err := s.InsertKey(expiredPEM, now.Add(-1*time.Hour)); err != nil {
		return err
	}

	if err := s.InsertKey(validPEM, now.Add(24*time.Hour)); err != nil {
		return err
	}

	return nil
}

func aesKeyFromEnv() ([]byte, error) {
	secret := os.Getenv("NOT_MY_KEY")
	if secret == "" {
		return nil, errors.New("NOT_MY_KEY environment variable is required")
	}
	hash := sha256.Sum256([]byte(secret))
	return hash[:], nil
}

func encryptPrivateKey(plain []byte) ([]byte, []byte, error) {
	key, err := aesKeyFromEnv()
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, iv, plain, nil)
	return ciphertext, iv, nil
}

func decryptPrivateKey(ciphertext []byte, iv []byte) ([]byte, error) {
	key, err := aesKeyFromEnv()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, iv, ciphertext, nil)
}

func (s *Store) InsertKey(privateKeyPEM []byte, exp time.Time) error {
	encrypted, iv, err := encryptPrivateKey(privateKeyPEM)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)`,
		encrypted,
		iv,
		exp.UTC().Unix(),
	)
	return err
}

func (s *Store) GetValidKey(now time.Time) (KeyRecord, bool, error) {
	row := s.db.QueryRow(
		`SELECT kid, key, iv, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1`,
		now.UTC().Unix(),
	)

	return s.scanKey(row)
}

func (s *Store) GetExpiredKey(now time.Time) (KeyRecord, bool, error) {
	row := s.db.QueryRow(
		`SELECT kid, key, iv, exp FROM keys WHERE exp <= ? ORDER BY exp ASC LIMIT 1`,
		now.UTC().Unix(),
	)

	return s.scanKey(row)
}

func (s *Store) scanKey(row *sql.Row) (KeyRecord, bool, error) {
	var kid int64
	var encrypted []byte
	var iv []byte
	var expUnix int64

	err := row.Scan(&kid, &encrypted, &iv, &expUnix)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return KeyRecord{}, false, nil
		}
		return KeyRecord{}, false, err
	}

	pemBytes, err := decryptPrivateKey(encrypted, iv)
	if err != nil {
		return KeyRecord{}, false, err
	}

	priv, err := DecodePrivateKeyFromPEM(pemBytes)
	if err != nil {
		return KeyRecord{}, false, err
	}

	return KeyRecord{
		KID:    kid,
		Expiry: time.Unix(expUnix, 0).UTC(),
		Priv:   priv,
	}, true, nil
}

func (s *Store) ActiveKeys(now time.Time) ([]KeyRecord, error) {
	rows, err := s.db.Query(
		`SELECT kid, key, iv, exp FROM keys WHERE exp > ? ORDER BY kid`,
		now.UTC().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []KeyRecord

	for rows.Next() {
		var kid int64
		var encrypted []byte
		var iv []byte
		var expUnix int64

		if err := rows.Scan(&kid, &encrypted, &iv, &expUnix); err != nil {
			return nil, err
		}

		pemBytes, err := decryptPrivateKey(encrypted, iv)
		if err != nil {
			return nil, err
		}

		priv, err := DecodePrivateKeyFromPEM(pemBytes)
		if err != nil {
			return nil, err
		}

		out = append(out, KeyRecord{
			KID:    kid,
			Expiry: time.Unix(expUnix, 0).UTC(),
			Priv:   priv,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$t=%d,m=%d,p=%d$%s$%s",
		argonTime,
		argonMemory,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	var timeCost uint32
	var memoryCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "t=%d,m=%d,p=%d", &timeCost, &memoryCost, &threads); err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	actual := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, threads, uint32(len(expected)))
	if len(actual) != len(expected) {
		return false
	}

	var diff byte
	for i := range actual {
		diff |= actual[i] ^ expected[i]
	}
	return diff == 0
}

func (s *Store) CreateUser(username, email, password string) error {
	passwordHash, err := HashPassword(password)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`INSERT INTO users(username, password_hash, email) VALUES (?, ?, ?)`,
		username,
		passwordHash,
		email,
	)
	return err
}

func (s *Store) AuthenticateUser(username, password string) (UserRecord, bool, error) {
	row := s.db.QueryRow(`SELECT id, username, email, password_hash FROM users WHERE username = ?`, username)

	var user UserRecord
	var passwordHash string
	if err := row.Scan(&user.ID, &user.Username, &user.Email, &passwordHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UserRecord{}, false, nil
		}
		return UserRecord{}, false, err
	}

	if !VerifyPassword(password, passwordHash) {
		return UserRecord{}, false, nil
	}

	_, _ = s.db.Exec(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, user.ID)
	return user, true, nil
}

func (s *Store) FindUserByUsername(username string) (UserRecord, bool, error) {
	row := s.db.QueryRow(`SELECT id, username, COALESCE(email, '') FROM users WHERE username = ?`, username)

	var user UserRecord
	if err := row.Scan(&user.ID, &user.Username, &user.Email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UserRecord{}, false, nil
		}
		return UserRecord{}, false, err
	}

	return user, true, nil
}

func (s *Store) LogAuthRequest(requestIP string, userID *int64) error {
	if userID == nil {
		_, err := s.db.Exec(`INSERT INTO auth_logs(request_ip, user_id) VALUES (?, NULL)`, requestIP)
		return err
	}

	_, err := s.db.Exec(`INSERT INTO auth_logs(request_ip, user_id) VALUES (?, ?)`, requestIP, *userID)
	return err
}

func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
