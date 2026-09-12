package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// wantsJSON checks if the client wants JSON response.
func wantsJSON(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

// writeText writes a plain text response.
func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeResponse writes either plain text or JSON based on the request.
func writeResponse(w http.ResponseWriter, r *http.Request, status int, text string, v interface{}) {
	if wantsJSON(r) {
		writeJSON(w, status, v)
	} else {
		writeText(w, status, text)
	}
}

// writeError writes an error response with a hint.
func writeError(w http.ResponseWriter, r *http.Request, status int, msg, hint string) {
	if wantsJSON(r) {
		writeJSON(w, status, map[string]string{
			"error": msg,
			"hint":  hint,
		})
	} else {
		writeText(w, status, "error: "+msg+" | hint: "+hint)
	}
}

// extractField extracts a field value from a plain text "key=value" line.
func extractField(line, key string) string {
	prefix := key + "="
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	rest := line[start:]
	// Find next space or end of line
	end := strings.Index(rest, " ")
	if end < 0 {
		return rest
	}
	return rest[:end]
}
