package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/relentlessworks/encodekit/internal/auth"
	"github.com/relentlessworks/encodekit/internal/model"
	"github.com/relentlessworks/encodekit/internal/store"
)

// Server holds all dependencies for the API.
type Server struct {
	auth  *auth.Manager
	store *store.Store
}

// NewServer creates a new API server.
func NewServer(a *auth.Manager, s *store.Store) *Server {
	return &Server{auth: a, store: s}
}

// Routes returns the HTTP handler with all routes registered.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/help", s.handleHelp)
	mux.HandleFunc("/.well-known/agent.md", s.handleHelp)
	mux.HandleFunc("/encodings", s.handleListEncodings)
	mux.HandleFunc("/mcp", s.handleMCP)

	// Auth endpoints
	mux.HandleFunc("/auth/request", s.handleAuthRequest)
	mux.HandleFunc("/auth/verify", s.handleAuthVerify)
	mux.HandleFunc("/auth/revoke", s.handleAuthRevoke)

	// Encode/Decode endpoints (require auth)
	mux.HandleFunc("/encode/", s.handleEncode)
	mux.HandleFunc("/decode/", s.handleDecode)

	// Operation management (require auth)
	mux.HandleFunc("/operations", s.handleListOperations)
	mux.HandleFunc("/operations/", s.handleOperation)

	// Audit log (require auth)
	mux.HandleFunc("/audit", s.handleAudit)

	// Root
	mux.HandleFunc("/", s.handleRoot)

	return mux
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, r, http.StatusNotFound, "not found", "GET /help for available endpoints")
		return
	}
	writeText(w, http.StatusOK, "encodekit — agentic-first encoding service. GET /help for instructions.")
}

func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	help := `encodekit — Agentic-First Encoding & Decoding Service

DESCRIPTION
  Encode and decode data in multiple formats: Base64, Base64URL, Base64Raw,
  Base32, Base32Hex, Hex, URL, HTML entities, ROT13, and Binary.

AUTH
  1. POST /auth/request   body: email=user@example.com
     → Returns: otp_sent=true (code logged to stderr in dev mode)
  2. POST /auth/verify    body: email=user@example.com code=123456
     → Returns: token=<hex> workspace=ws_xxxxx
  3. Use token in all subsequent requests:
     Authorization: Bearer <token>

ENDPOINTS

  GET  /encodings
    List all supported encoding types.
    → base64 base64url base64raw base32 base32hex hex url html rot13 binary

  POST /encode/{type}     body: data=<text>&save=true
    Encode text to the specified format.
    → type=base64 input=hello output=aGVsbG8= handle=enc_xxxxx (if saved)
    Example: POST /encode/base64  body: data=Hello World

  POST /decode/{type}     body: data=<encoded>&save=true
    Decode encoded data back to text.
    → type=base64 input=aGVsbG8= output=hello handle=dec_xxxxx (if saved)
    Example: POST /decode/base64  body: data=aGVsbG8=

  GET  /operations
    List saved operations.
    → handle=enc_xxxxx type=base64 direction=encode input=hello output=aGVsbG8=

  GET  /operations/{handle}
    Get a specific saved operation.

  DELETE /operations/{handle}
    Delete a saved operation.

  GET  /audit?limit=10
    View recent audit log entries.

  POST /auth/revoke       body: (uses bearer token)
    Revoke the current token.

  GET  /help
    This help text.

  GET  /.well-known/agent.md
    Same as /help (for agent discovery).

  POST /mcp
    MCP JSON-RPC 2.0 endpoint for chat client integrations.

RESPONSE FORMAT
  Plain text by default (one labeled line per record).
  JSON available via Accept: application/json or ?format=json.

ERRORS
  All 4xx errors include a hint:
  error: <message> | hint: <what to do next>
`
	writeText(w, http.StatusOK, help)
}

func (s *Server) handleListEncodings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET /encodings")
		return
	}
	encodings := make([]string, len(model.SupportedEncodings))
	for i, e := range model.SupportedEncodings {
		encodings[i] = string(e)
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"encodings": encodings,
		})
	} else {
		writeText(w, http.StatusOK, strings.Join(encodings, " "))
	}
}

func (s *Server) handleAuthRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST /auth/request with email")
		return
	}
	r.ParseForm()
	email := r.FormValue("email")
	if email == "" {
		writeError(w, r, http.StatusBadRequest, "missing email", "POST /auth/request with body: email=user@example.com")
		return
	}
	_, err := s.auth.RequestOTP(email)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "ensure email is a valid email address")
		return
	}
	writeResponse(w, r, http.StatusOK, "otp_sent=true email="+email, map[string]interface{}{
		"otp_sent": true,
		"email":    email,
	})
}

func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST /auth/verify with email and code")
		return
	}
	r.ParseForm()
	email := r.FormValue("email")
	code := r.FormValue("code")
	if email == "" || code == "" {
		writeError(w, r, http.StatusBadRequest, "missing email or code", "POST /auth/verify with body: email=user@example.com code=123456")
		return
	}
	token, err := s.auth.VerifyOTP(email, code)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, err.Error(), "request a new OTP via POST /auth/request")
		return
	}
	s.store.AddAuditEntry(store.NewAuditEntry("auth.verify", email, "token issued"))
	writeResponse(w, r, http.StatusOK,
		fmt.Sprintf("token=%s workspace=%s email=%s", token.Value, token.Workspace, token.Email),
		map[string]interface{}{
			"token":     token.Value,
			"workspace": token.Workspace,
			"email":     token.Email,
		})
}

func (s *Server) handleAuthRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST /auth/revoke with bearer token")
		return
	}
	tok := getBearerToken(r)
	if tok == "" {
		writeError(w, r, http.StatusUnauthorized, "missing auth token", "include Authorization: Bearer <token> header")
		return
	}
	if s.auth.RevokeToken(tok) {
		writeResponse(w, r, http.StatusOK, "revoked=true", map[string]interface{}{"revoked": true})
	} else {
		writeError(w, r, http.StatusNotFound, "token not found", "ensure you are sending a valid bearer token")
	}
}

func (s *Server) handleEncode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST /encode/{type} with data")
		return
	}
	tok := getBearerToken(r)
	if tok == "" {
		writeError(w, r, http.StatusUnauthorized, "missing auth token", "call POST /auth/request with email to get an OTP, then POST /auth/verify to get a bearer token")
		return
	}
	tokenInfo, ok := s.auth.ValidateToken(tok)
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "invalid token", "request a new token via POST /auth/request then POST /auth/verify")
		return
	}

	// Extract encoding type from path
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/encode/"), "/")
	encTypeStr := pathParts[0]
	if !model.IsValidEncoding(encTypeStr) {
		writeError(w, r, http.StatusBadRequest, "unsupported encoding type: "+encTypeStr, "use GET /encodings to list supported types")
		return
	}

	r.ParseForm()
	data := r.FormValue("data")
	if data == "" {
		writeError(w, r, http.StatusBadRequest, "missing data", "POST /encode/"+encTypeStr+" with body: data=<text to encode>")
		return
	}

	encType := model.EncodingType(encTypeStr)
	output, err := Encode(encType, data)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "check the encoding type and input data")
		return
	}

	save := r.FormValue("save") == "true"
	var handle string
	if save {
		handle = model.GenerateHandle("enc")
		op := &model.Operation{
			Handle:    handle,
			Type:      encType,
			Direction: "encode",
			Input:     data,
			Output:    output,
			CreatedAt: time.Now(),
		}
		s.store.SaveOperation(op)
		s.store.AddAuditEntry(store.NewAuditEntry("encode", tokenInfo.Email, fmt.Sprintf("type=%s handle=%s", encType, handle)))
	}

	textResp := fmt.Sprintf("type=%s input=%s output=%s", encType, data, output)
	if handle != "" {
		textResp += " handle=" + handle
	}
	respMap := map[string]interface{}{
		"type":   encType,
		"input":  data,
		"output": output,
	}
	if handle != "" {
		respMap["handle"] = handle
	}
	writeResponse(w, r, http.StatusOK, textResp, respMap)
}

func (s *Server) handleDecode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST /decode/{type} with data")
		return
	}
	tok := getBearerToken(r)
	if tok == "" {
		writeError(w, r, http.StatusUnauthorized, "missing auth token", "call POST /auth/request with email to get an OTP, then POST /auth/verify to get a bearer token")
		return
	}
	tokenInfo, ok := s.auth.ValidateToken(tok)
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "invalid token", "request a new token via POST /auth/request then POST /auth/verify")
		return
	}

	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/decode/"), "/")
	encTypeStr := pathParts[0]
	if !model.IsValidEncoding(encTypeStr) {
		writeError(w, r, http.StatusBadRequest, "unsupported encoding type: "+encTypeStr, "use GET /encodings to list supported types")
		return
	}

	r.ParseForm()
	data := r.FormValue("data")
	if data == "" {
		writeError(w, r, http.StatusBadRequest, "missing data", "POST /decode/"+encTypeStr+" with body: data=<encoded text to decode>")
		return
	}

	encType := model.EncodingType(encTypeStr)
	output, err := Decode(encType, data)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "check the encoding type and input data format")
		return
	}

	save := r.FormValue("save") == "true"
	var handle string
	if save {
		handle = model.GenerateHandle("dec")
		op := &model.Operation{
			Handle:    handle,
			Type:      encType,
			Direction: "decode",
			Input:     data,
			Output:    output,
			CreatedAt: time.Now(),
		}
		s.store.SaveOperation(op)
		s.store.AddAuditEntry(store.NewAuditEntry("decode", tokenInfo.Email, fmt.Sprintf("type=%s handle=%s", encType, handle)))
	}

	textResp := fmt.Sprintf("type=%s input=%s output=%s", encType, data, output)
	if handle != "" {
		textResp += " handle=" + handle
	}
	respMap := map[string]interface{}{
		"type":   encType,
		"input":  data,
		"output": output,
	}
	if handle != "" {
		respMap["handle"] = handle
	}
	writeResponse(w, r, http.StatusOK, textResp, respMap)
}

func (s *Server) handleListOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET /operations")
		return
	}
	tok := getBearerToken(r)
	if tok == "" {
		writeError(w, r, http.StatusUnauthorized, "missing auth token", "call POST /auth/request with email to get an OTP, then POST /auth/verify to get a bearer token")
		return
	}
	if _, ok := s.auth.ValidateToken(tok); !ok {
		writeError(w, r, http.StatusUnauthorized, "invalid token", "request a new token via POST /auth/request then POST /auth/verify")
		return
	}

	ops := s.store.ListOperations()
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"operations": ops,
			"count":      len(ops),
		})
		return
	}
	if len(ops) == 0 {
		writeText(w, http.StatusOK, "no saved operations")
		return
	}
	var lines []string
	for _, op := range ops {
		lines = append(lines, fmt.Sprintf("handle=%s type=%s direction=%s input=%s output=%s",
			op.Handle, op.Type, op.Direction, op.Input, op.Output))
	}
	writeText(w, http.StatusOK, strings.Join(lines, "\n"))
}

func (s *Server) handleOperation(w http.ResponseWriter, r *http.Request) {
	tok := getBearerToken(r)
	if tok == "" {
		writeError(w, r, http.StatusUnauthorized, "missing auth token", "call POST /auth/request with email to get an OTP, then POST /auth/verify to get a bearer token")
		return
	}
	if _, ok := s.auth.ValidateToken(tok); !ok {
		writeError(w, r, http.StatusUnauthorized, "invalid token", "request a new token via POST /auth/request then POST /auth/verify")
		return
	}

	handle := strings.TrimPrefix(r.URL.Path, "/operations/")
	if handle == "" {
		writeError(w, r, http.StatusBadRequest, "missing operation handle", "use GET /operations/{handle} or DELETE /operations/{handle}")
		return
	}

	switch r.Method {
	case http.MethodGet:
		op, ok := s.store.GetOperation(handle)
		if !ok {
			writeError(w, r, http.StatusNotFound, "operation not found: "+handle, "use GET /operations to list all saved operations")
			return
		}
		writeResponse(w, r, http.StatusOK,
			fmt.Sprintf("handle=%s type=%s direction=%s input=%s output=%s created_at=%s",
				op.Handle, op.Type, op.Direction, op.Input, op.Output, op.CreatedAt.Format(time.RFC3339)),
			op)
	case http.MethodDelete:
		if s.store.DeleteOperation(handle) {
			writeResponse(w, r, http.StatusOK, "deleted=true handle="+handle, map[string]interface{}{"deleted": true, "handle": handle})
		} else {
			writeError(w, r, http.StatusNotFound, "operation not found: "+handle, "use GET /operations to list all saved operations")
		}
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET or DELETE /operations/{handle}")
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET /audit?limit=10")
		return
	}
	tok := getBearerToken(r)
	if tok == "" {
		writeError(w, r, http.StatusUnauthorized, "missing auth token", "call POST /auth/request with email to get an OTP, then POST /auth/verify to get a bearer token")
		return
	}
	if _, ok := s.auth.ValidateToken(tok); !ok {
		writeError(w, r, http.StatusUnauthorized, "invalid token", "request a new token via POST /auth/request then POST /auth/verify")
		return
	}

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	entries := s.store.ListAuditEntries(limit)
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"entries": entries,
			"count":   len(entries),
		})
		return
	}
	if len(entries) == 0 {
		writeText(w, http.StatusOK, "no audit entries")
		return
	}
	var lines []string
	for _, e := range entries {
		lines = append(lines, fmt.Sprintf("id=%s action=%s actor=%s detail=%s time=%s",
			e.ID, e.Action, e.Actor, e.Detail, e.Timestamp.Format(time.RFC3339)))
	}
	writeText(w, http.StatusOK, strings.Join(lines, "\n"))
}

func getBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}
