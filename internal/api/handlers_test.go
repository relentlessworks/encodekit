package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/relentlessworks/encodekit/internal/auth"
	"github.com/relentlessworks/encodekit/internal/store"
)

func setupTestServer(t *testing.T) (*Server, *auth.Manager) {
	a := auth.New("test-secret")
	s := store.New("") // in-memory
	return NewServer(a, s), a
}

func getTestToken(t *testing.T, server *Server, mgr *auth.Manager) string {
	mgr.RequestOTP("test@example.com")
	// We need to get the OTP - request it and capture from the manager
	// Since OTP is stored internally, we'll use the verify endpoint with a known pattern
	// Actually, let's just call verify with the right code by requesting first
	// For testing, we'll use a different approach - directly create a token
	token, err := mgr.VerifyOTP("test@example.com", "")
	_ = token
	_ = err
	// This won't work because we don't know the code. Let's use a helper.
	return ""
}

// Helper to get a valid token for testing
func getValidToken(t *testing.T, mgr *auth.Manager) string {
	// Request OTP
	code, _ := mgr.RequestOTP("test@example.com")
	token, err := mgr.VerifyOTP("test@example.com", code)
	if err != nil {
		t.Fatalf("failed to get token: %v", err)
	}
	return token.Value
}

func TestRoot(t *testing.T) {
	server, _ := setupTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "encodekit") {
		t.Errorf("expected body to contain 'encodekit', got: %s", w.Body.String())
	}
}

func TestHelp(t *testing.T) {
	server, _ := setupTestServer(t)
	req := httptest.NewRequest("GET", "/help", nil)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "AUTH") {
		t.Errorf("help should contain AUTH section")
	}
	if !strings.Contains(body, "encode") {
		t.Errorf("help should contain encode endpoint")
	}
}

func TestAgentMD(t *testing.T) {
	server, _ := setupTestServer(t)
	req := httptest.NewRequest("GET", "/.well-known/agent.md", nil)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestListEncodings(t *testing.T) {
	server, _ := setupTestServer(t)
	req := httptest.NewRequest("GET", "/encodings", nil)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, enc := range []string{"base64", "base32", "hex", "url", "html", "rot13", "binary"} {
		if !strings.Contains(body, enc) {
			t.Errorf("encodings should contain %s, got: %s", enc, body)
		}
	}
}

func TestAuthRequest(t *testing.T) {
	server, _ := setupTestServer(t)
	form := url.Values{"email": {"test@example.com"}}
	req := httptest.NewRequest("POST", "/auth/request", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "otp_sent=true") {
		t.Errorf("expected otp_sent=true, got: %s", w.Body.String())
	}
}

func TestAuthRequestMissingEmail(t *testing.T) {
	server, _ := setupTestServer(t)
	req := httptest.NewRequest("POST", "/auth/request", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "hint:") {
		t.Errorf("error should include hint, got: %s", w.Body.String())
	}
}

func TestAuthVerify(t *testing.T) {
	server, mgr := setupTestServer(t)
	code, _ := mgr.RequestOTP("test@example.com")

	form := url.Values{"email": {"test@example.com"}, "code": {code}}
	req := httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "token=") {
		t.Errorf("expected token in response, got: %s", body)
	}
	if !strings.Contains(body, "workspace=") {
		t.Errorf("expected workspace in response, got: %s", body)
	}
}

func TestAuthVerifyBadCode(t *testing.T) {
	server, mgr := setupTestServer(t)
	mgr.RequestOTP("test@example.com")

	form := url.Values{"email": {"test@example.com"}, "code": {"000000"}}
	req := httptest.NewRequest("POST", "/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestEncodeWithoutAuth(t *testing.T) {
	server, _ := setupTestServer(t)
	form := url.Values{"data": {"hello"}}
	req := httptest.NewRequest("POST", "/encode/base64", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

func TestEncodeBase64(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"Hello World"}}
	req := httptest.NewRequest("POST", "/encode/base64", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "output=SGVsbG8gV29ybGQ=") {
		t.Errorf("expected base64 output, got: %s", body)
	}
}

func TestDecodeBase64(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"SGVsbG8gV29ybGQ="}}
	req := httptest.NewRequest("POST", "/decode/base64", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "output=Hello World") {
		t.Errorf("expected decoded output, got: %s", body)
	}
}

func TestEncodeHex(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"hi"}}
	req := httptest.NewRequest("POST", "/encode/hex", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "output=6869") {
		t.Errorf("expected hex output 6869, got: %s", w.Body.String())
	}
}

func TestDecodeHex(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"6869"}}
	req := httptest.NewRequest("POST", "/decode/hex", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "output=hi") {
		t.Errorf("expected decoded output 'hi', got: %s", w.Body.String())
	}
}

func TestEncodeROT13(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"Hello"}}
	req := httptest.NewRequest("POST", "/encode/rot13", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "output=Uryyb") {
		t.Errorf("expected ROT13 output 'Uryyb', got: %s", w.Body.String())
	}
}

func TestDecodeROT13(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"Uryyb"}}
	req := httptest.NewRequest("POST", "/decode/rot13", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "output=Hello") {
		t.Errorf("expected decoded 'Hello', got: %s", w.Body.String())
	}
}

func TestEncodeBinary(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"A"}}
	req := httptest.NewRequest("POST", "/encode/binary", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "output=01000001") {
		t.Errorf("expected binary output '01000001', got: %s", w.Body.String())
	}
}

func TestDecodeBinary(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"01000001"}}
	req := httptest.NewRequest("POST", "/decode/binary", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "output=A") {
		t.Errorf("expected decoded 'A', got: %s", w.Body.String())
	}
}

func TestEncodeURLEnc(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"hello world&foo=bar"}}
	req := httptest.NewRequest("POST", "/encode/url", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "output=hello+world%26foo%3Dbar") {
		t.Errorf("expected URL-encoded output, got: %s", w.Body.String())
	}
}

func TestEncodeHTML(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"<script>alert('xss')</script>"}}
	req := httptest.NewRequest("POST", "/encode/html", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected HTML-encoded output, got: %s", body)
	}
}

func TestEncodeWithSave(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"test"}, "save": {"true"}}
	req := httptest.NewRequest("POST", "/encode/base64", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "handle=enc_") {
		t.Errorf("expected handle in response when save=true, got: %s", body)
	}
}

func TestListOperations(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	// Save an operation first
	form := url.Values{"data": {"test"}, "save": {"true"}}
	req := httptest.NewRequest("POST", "/encode/base64", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	// List operations
	req2 := httptest.NewRequest("GET", "/operations", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	server.Routes().ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "handle=enc_") {
		t.Errorf("expected operation in list, got: %s", w2.Body.String())
	}
}

func TestUnsupportedEncoding(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"test"}}
	req := httptest.NewRequest("POST", "/encode/invalid", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "hint:") {
		t.Errorf("error should include hint, got: %s", w.Body.String())
	}
}

func TestJSONResponse(t *testing.T) {
	server, _ := setupTestServer(t)
	req := httptest.NewRequest("GET", "/encodings?format=json", nil)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
		t.Errorf("expected JSON content type, got: %s", w.Header().Get("Content-Type"))
	}
}

func TestNotFound(t *testing.T) {
	server, _ := setupTestServer(t)
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestMCPInitialize(t *testing.T) {
	server, _ := setupTestServer(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "encodekit") {
		t.Errorf("expected server name in response, got: %s", w.Body.String())
	}
}

func TestMCPListTools(t *testing.T) {
	server, _ := setupTestServer(t)
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	respBody := w.Body.String()
	if !strings.Contains(respBody, "encode") {
		t.Errorf("expected encode tool, got: %s", respBody)
	}
	if !strings.Contains(respBody, "decode") {
		t.Errorf("expected decode tool, got: %s", respBody)
	}
}

func TestMCPCallEncode(t *testing.T) {
	server, _ := setupTestServer(t)
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"encode","arguments":{"type":"base64","data":"hello"}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "aGVsbG8=") {
		t.Errorf("expected base64 encoded 'hello', got: %s", w.Body.String())
	}
}

func TestMCPCallDecode(t *testing.T) {
	server, _ := setupTestServer(t)
	body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"decode","arguments":{"type":"base64","data":"aGVsbG8="}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "hello") {
		t.Errorf("expected decoded 'hello', got: %s", w.Body.String())
	}
}

func TestMCPCallListEncodings(t *testing.T) {
	server, _ := setupTestServer(t)
	body := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_encodings","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "base64") {
		t.Errorf("expected base64 in encodings list, got: %s", w.Body.String())
	}
}

func TestAuditLog(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	// Do an encode to generate audit entry
	form := url.Values{"data": {"test"}, "save": {"true"}}
	req := httptest.NewRequest("POST", "/encode/base64", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	// Check audit log
	req2 := httptest.NewRequest("GET", "/audit?limit=10", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	server.Routes().ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	body := w2.Body.String()
	if !strings.Contains(body, "action=encode") {
		t.Errorf("expected encode action in audit log, got: %s", body)
	}
}

func TestRevokeToken(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	req := httptest.NewRequest("POST", "/auth/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "revoked=true") {
		t.Errorf("expected revoked=true, got: %s", w.Body.String())
	}

	// Verify token no longer works
	req2 := httptest.NewRequest("GET", "/operations", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	server.Routes().ServeHTTP(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 after revoke, got %d", w2.Code)
	}
}

func TestEncodeBase32(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"hi"}}
	req := httptest.NewRequest("POST", "/encode/base32", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// "hi" = 0x68 0x69 = NBUQ====
	if !strings.Contains(w.Body.String(), "output=NBUQ") {
		t.Errorf("expected base32 output containing NBUQ, got: %s", w.Body.String())
	}
}

func TestDecodeBase32(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"NBUQ===="}}
	req := httptest.NewRequest("POST", "/decode/base32", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "output=hi") {
		t.Errorf("expected decoded 'hi', got: %s", w.Body.String())
	}
}

func TestEncodeBase64URL(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"???"}}
	req := httptest.NewRequest("POST", "/encode/base64url", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// "???" = 3F 3F 3F = Pz8_ in URL-safe base64
	if !strings.Contains(w.Body.String(), "output=Pz8_") {
		t.Errorf("expected base64url output Pz8_, got: %s", w.Body.String())
	}
}

func TestEncodeBase64Raw(t *testing.T) {
	server, mgr := setupTestServer(t)
	token := getValidToken(t, mgr)

	form := url.Values{"data": {"hi"}}
	req := httptest.NewRequest("POST", "/encode/base64raw", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// Raw std encoding has no padding: "hi" = aGk=
	if !strings.Contains(w.Body.String(), "output=aGk") {
		t.Errorf("expected base64raw output aGk, got: %s", w.Body.String())
	}
}
