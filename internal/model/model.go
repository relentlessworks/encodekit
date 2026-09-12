package model

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
	"time"
)

// EncodingType represents a supported encoding format.
type EncodingType string

const (
	TypeBase64    EncodingType = "base64"
	TypeBase64URL EncodingType = "base64url"
	TypeBase64Raw EncodingType = "base64raw"
	TypeBase32    EncodingType = "base32"
	TypeBase32Hex EncodingType = "base32hex"
	TypeHex       EncodingType = "hex"
	TypeURLEnc    EncodingType = "url"
	TypeHTML      EncodingType = "html"
	TypeROT13     EncodingType = "rot13"
	TypeBinary    EncodingType = "binary"
)

// SupportedEncodings lists all available encoding types.
var SupportedEncodings = []EncodingType{
	TypeBase64, TypeBase64URL, TypeBase64Raw,
	TypeBase32, TypeBase32Hex,
	TypeHex, TypeURLEnc, TypeHTML, TypeROT13, TypeBinary,
}

// IsValidEncoding checks if an encoding type is supported.
func IsValidEncoding(t string) bool {
	for _, e := range SupportedEncodings {
		if string(e) == t {
			return true
		}
	}
	return false
}

// Operation represents a saved encode/decode operation.
type Operation struct {
	Handle    string       `json:"handle"`
	Type      EncodingType `json:"type"`
	Direction string       `json:"direction"`
	Input     string       `json:"input"`
	Output    string       `json:"output"`
	CreatedAt time.Time    `json:"created_at"`
}

// Workspace represents a tenant workspace.
type Workspace struct {
	Handle    string    `json:"handle"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditEntry represents an audit log record.
type AuditEntry struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`
	Detail    string    `json:"detail"`
	Timestamp time.Time `json:"timestamp"`
}

// Token represents an auth bearer token.
type Token struct {
	Value     string    `json:"value"`
	Email     string    `json:"email"`
	Workspace string    `json:"workspace"`
	CreatedAt time.Time `json:"created_at"`
}

// OTP represents a one-time password.
type OTP struct {
	Code      string    `json:"code"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
}

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// GenerateHandle creates a short stable handle with a type prefix.
func GenerateHandle(prefix string) string {
	b := make([]byte, 5)
	rand.Read(b)
	return prefix + "_" + strings.ToLower(b32.EncodeToString(b))[:5]
}
