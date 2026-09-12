package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/relentlessworks/encodekit/internal/model"
)

// Manager handles OTP generation, verification, and token management.
type Manager struct {
	secret string
	mu     sync.RWMutex
	otps   map[string]*model.OTP
	tokens map[string]*model.Token
}

// New creates a new auth manager.
func New(secret string) *Manager {
	return &Manager{
		secret: secret,
		otps:   make(map[string]*model.OTP),
		tokens: make(map[string]*model.Token),
	}
}

// RequestOTP generates a 6-digit OTP for the given email.
func (m *Manager) RequestOTP(email string) (string, error) {
	if email == "" {
		return "", fmt.Errorf("email is required")
	}

	code := generateOTP()
	m.mu.Lock()
	m.otps[email] = &model.OTP{
		Code:      code,
		Email:     email,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	m.mu.Unlock()

	fmt.Fprintf(os.Stderr, "OTP for %s: %s\n", email, code)
	return code, nil
}

// VerifyOTP validates the OTP and returns a bearer token.
func (m *Manager) VerifyOTP(email, code string) (*model.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	otp, ok := m.otps[email]
	if !ok {
		return nil, fmt.Errorf("no OTP requested for this email")
	}

	if time.Now().After(otp.ExpiresAt) {
		delete(m.otps, email)
		return nil, fmt.Errorf("OTP has expired")
	}

	if otp.Code != code {
		return nil, fmt.Errorf("invalid OTP code")
	}

	delete(m.otps, email)

	tokenValue := generateToken(m.secret, email)
	wsHandle := model.GenerateHandle("ws")

	token := &model.Token{
		Value:     tokenValue,
		Email:     email,
		Workspace: wsHandle,
		CreatedAt: time.Now(),
	}
	m.tokens[tokenValue] = token

	return token, nil
}

// ValidateToken checks if a bearer token is valid.
func (m *Manager) ValidateToken(value string) (*model.Token, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tokens[value]
	return t, ok
}

// RevokeToken removes a token.
func (m *Manager) RevokeToken(value string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tokens[value]; ok {
		delete(m.tokens, value)
		return true
	}
	return false
}

func generateOTP() string {
	b := make([]byte, 4)
	rand.Read(b)
	code := int(b[0])%1000000
	if code < 100000 {
		code += 100000
	}
	return fmt.Sprintf("%06d", code)
}

func generateToken(secret, email string) string {
	h := sha256.New()
	h.Write([]byte(secret + email + time.Now().String() + randomHex(8)))
	return hex.EncodeToString(h.Sum(nil))
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
