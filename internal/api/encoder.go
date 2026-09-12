package api

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"strconv"
	"strings"

	"github.com/relentlessworks/encodekit/internal/model"
)

// Encode converts input data to the specified encoding type.
func Encode(encType model.EncodingType, input string) (string, error) {
	data := []byte(input)
	switch encType {
	case model.TypeBase64:
		return base64.StdEncoding.EncodeToString(data), nil
	case model.TypeBase64URL:
		return base64.URLEncoding.EncodeToString(data), nil
	case model.TypeBase64Raw:
		return base64.RawStdEncoding.EncodeToString(data), nil
	case model.TypeBase32:
		return base32.StdEncoding.EncodeToString(data), nil
	case model.TypeBase32Hex:
		return base32.HexEncoding.EncodeToString(data), nil
	case model.TypeHex:
		return hex.EncodeToString(data), nil
	case model.TypeURLEnc:
		return url.QueryEscape(input), nil
	case model.TypeHTML:
		return html.EscapeString(input), nil
	case model.TypeROT13:
		return rot13(input), nil
	case model.TypeBinary:
		return toBinary(data), nil
	default:
		return "", fmt.Errorf("unsupported encoding type: %s | hint: use GET /encodings to list supported types", encType)
	}
}

// Decode converts encoded data back to its original form.
func Decode(encType model.EncodingType, input string) (string, error) {
	switch encType {
	case model.TypeBase64:
		b, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return "", fmt.Errorf("invalid base64 input | hint: ensure input is valid standard base64 encoded data")
		}
		return string(b), nil
	case model.TypeBase64URL:
		b, err := base64.URLEncoding.DecodeString(input)
		if err != nil {
			return "", fmt.Errorf("invalid base64url input | hint: ensure input is valid URL-safe base64 encoded data")
		}
		return string(b), nil
	case model.TypeBase64Raw:
		b, err := base64.RawStdEncoding.DecodeString(input)
		if err != nil {
			return "", fmt.Errorf("invalid base64raw input | hint: ensure input is valid unpadded standard base64 encoded data")
		}
		return string(b), nil
	case model.TypeBase32:
		b, err := base32.StdEncoding.DecodeString(strings.ToUpper(input))
		if err != nil {
			return "", fmt.Errorf("invalid base32 input | hint: ensure input is valid standard base32 encoded data (A-Z, 2-7)")
		}
		return string(b), nil
	case model.TypeBase32Hex:
		b, err := base32.HexEncoding.DecodeString(strings.ToUpper(input))
		if err != nil {
			return "", fmt.Errorf("invalid base32hex input | hint: ensure input is valid hex base32 encoded data (0-9, A-V)")
		}
		return string(b), nil
	case model.TypeHex:
		b, err := hex.DecodeString(input)
		if err != nil {
			return "", fmt.Errorf("invalid hex input | hint: ensure input is valid hexadecimal (0-9, a-f)")
		}
		return string(b), nil
	case model.TypeURLEnc:
		s, err := url.QueryUnescape(input)
		if err != nil {
			return "", fmt.Errorf("invalid URL-encoded input | hint: ensure input is valid percent-encoded data")
		}
		return s, nil
	case model.TypeHTML:
		return html.UnescapeString(input), nil
	case model.TypeROT13:
		return rot13(input), nil
	case model.TypeBinary:
		return fromBinary(input)
	default:
		return "", fmt.Errorf("unsupported encoding type: %s | hint: use GET /encodings to list supported types", encType)
	}
}

func rot13(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune((r-'a'+13)%26 + 'a')
		case r >= 'A' && r <= 'Z':
			b.WriteRune((r-'A'+13)%26 + 'A')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func toBinary(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%08b", b)
	}
	return strings.Join(parts, " ")
}

func fromBinary(input string) (string, error) {
	input = strings.TrimSpace(input)
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return "", nil
	}
	data := make([]byte, len(parts))
	for i, p := range parts {
		val, err := strconv.ParseUint(p, 2, 8)
		if err != nil {
			return "", fmt.Errorf("invalid binary input | hint: ensure input is space-separated 8-bit binary values (e.g. 01001000 01101001)")
		}
		data[i] = byte(val)
	}
	return string(data), nil
}
