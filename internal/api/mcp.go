package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/relentlessworks/encodekit/internal/model"
)

// MCPRequest is a JSON-RPC 2.0 request.
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// MCPResponse is a JSON-RPC 2.0 response.
type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCError    `json:"error,omitempty"`
}

// MCError is a JSON-RPC error.
type MCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema struct {
		Type       string                 `json:"type"`
		Properties map[string]interface{} `json:"properties"`
		Required   []string               `json:"required"`
	} `json:"inputSchema"`
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST /mcp with JSON-RPC 2.0 body")
		return
	}

	var req MCPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, MCPResponse{
			JSONRPC: "2.0",
			Error:   &MCError{Code: -32700, Message: "parse error"},
		})
		return
	}

	switch req.Method {
	case "initialize":
		s.mcpInitialize(w, req)
	case "tools/list":
		s.mcpListTools(w, req)
	case "tools/call":
		s.mcpCallTool(w, req)
	default:
		writeJSON(w, http.StatusOK, MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &MCError{Code: -32601, Message: "method not found: " + req.Method},
		})
	}
}

func (s *Server) mcpInitialize(w http.ResponseWriter, req MCPRequest) {
	writeJSON(w, http.StatusOK, MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "encodekit",
				"version": "0.1.0",
			},
		},
	})
}

func (s *Server) mcpListTools(w http.ResponseWriter, req MCPRequest) {
	tools := []mcpTool{
		mcpTool{
			Name:        "encode",
			Description: "Encode text to a specified format (base64, base64url, base64raw, base32, base32hex, hex, url, html, rot13, binary)",
			InputSchema: struct {
				Type       string                 `json:"type"`
				Properties map[string]interface{} `json:"properties"`
				Required   []string               `json:"required"`
			}{
				Type: "object",
				Properties: map[string]interface{}{
					"type": map[string]interface{}{
						"type":        "string",
						"description": "Encoding type: base64, base64url, base64raw, base32, base32hex, hex, url, html, rot13, binary",
					},
					"data": map[string]interface{}{
						"type":        "string",
						"description": "Text to encode",
					},
				},
				Required: []string{"type", "data"},
			},
		},
		mcpTool{
			Name:        "decode",
			Description: "Decode encoded data back to text (base64, base64url, base64raw, base32, base32hex, hex, url, html, rot13, binary)",
			InputSchema: struct {
				Type       string                 `json:"type"`
				Properties map[string]interface{} `json:"properties"`
				Required   []string               `json:"required"`
			}{
				Type: "object",
				Properties: map[string]interface{}{
					"type": map[string]interface{}{
						"type":        "string",
						"description": "Encoding type: base64, base64url, base64raw, base32, base32hex, hex, url, html, rot13, binary",
					},
					"data": map[string]interface{}{
						"type":        "string",
						"description": "Encoded data to decode",
					},
				},
				Required: []string{"type", "data"},
			},
		},
		mcpTool{
			Name:        "list_encodings",
			Description: "List all supported encoding types",
			InputSchema: struct {
				Type       string                 `json:"type"`
				Properties map[string]interface{} `json:"properties"`
				Required   []string               `json:"required"`
			}{
				Type:       "object",
				Properties: map[string]interface{}{},
				Required:   []string{},
			},
		},
		mcpTool{
			Name:        "list_operations",
			Description: "List all saved encoding/decoding operations",
			InputSchema: struct {
				Type       string                 `json:"type"`
				Properties map[string]interface{} `json:"properties"`
				Required   []string               `json:"required"`
			}{
				Type:       "object",
				Properties: map[string]interface{}{},
				Required:   []string{},
			},
		},
		mcpTool{
			Name:        "get_operation",
			Description: "Get a specific saved operation by handle",
			InputSchema: struct {
				Type       string                 `json:"type"`
				Properties map[string]interface{} `json:"properties"`
				Required   []string               `json:"required"`
			}{
				Type: "object",
				Properties: map[string]interface{}{
					"handle": map[string]interface{}{
						"type":        "string",
						"description": "Operation handle (e.g. enc_xxxxx)",
					},
				},
				Required: []string{"handle"},
			},
		},
		mcpTool{
			Name:        "delete_operation",
			Description: "Delete a saved operation by handle",
			InputSchema: struct {
				Type       string                 `json:"type"`
				Properties map[string]interface{} `json:"properties"`
				Required   []string               `json:"required"`
			}{
				Type: "object",
				Properties: map[string]interface{}{
					"handle": map[string]interface{}{
						"type":        "string",
						"description": "Operation handle to delete (e.g. enc_xxxxx)",
					},
				},
				Required: []string{"handle"},
			},
		},
		mcpTool{
			Name:        "audit_log",
			Description: "View recent audit log entries",
			InputSchema: struct {
				Type       string                 `json:"type"`
				Properties map[string]interface{} `json:"properties"`
				Required   []string               `json:"required"`
			}{
				Type: "object",
				Properties: map[string]interface{}{
					"limit": map[string]interface{}{
						"type":        "number",
						"description": "Maximum number of entries to return (default 20)",
					},
				},
				Required: []string{},
			},
		},
	}

	writeJSON(w, http.StatusOK, MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	})
}

func (s *Server) mcpCallTool(w http.ResponseWriter, req MCPRequest) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments,omitempty"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSON(w, http.StatusOK, MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &MCError{Code: -32602, Message: "invalid params"},
		})
		return
	}

	switch params.Name {
	case "encode":
		s.mcpEncode(w, req, params.Arguments)
	case "decode":
		s.mcpDecode(w, req, params.Arguments)
	case "list_encodings":
		encodings := make([]string, len(model.SupportedEncodings))
		for i, e := range model.SupportedEncodings {
			encodings[i] = string(e)
		}
		s.mcpResult(w, req, strings.Join(encodings, " "))
	case "list_operations":
		ops := s.store.ListOperations()
		var lines []string
		for _, op := range ops {
			lines = append(lines, fmt.Sprintf("handle=%s type=%s direction=%s input=%s output=%s",
				op.Handle, op.Type, op.Direction, op.Input, op.Output))
		}
		if len(lines) == 0 {
			s.mcpResult(w, req, "no saved operations")
		} else {
			s.mcpResult(w, req, strings.Join(lines, "\n"))
		}
	case "get_operation":
		var args struct {
			Handle string `json:"handle"`
		}
		json.Unmarshal(params.Arguments, &args)
		op, ok := s.store.GetOperation(args.Handle)
		if !ok {
			s.mcpError(w, req, "operation not found: "+args.Handle)
			return
		}
		s.mcpResult(w, req, fmt.Sprintf("handle=%s type=%s direction=%s input=%s output=%s",
			op.Handle, op.Type, op.Direction, op.Input, op.Output))
	case "delete_operation":
		var args struct {
			Handle string `json:"handle"`
		}
		json.Unmarshal(params.Arguments, &args)
		if s.store.DeleteOperation(args.Handle) {
			s.mcpResult(w, req, "deleted=true handle="+args.Handle)
		} else {
			s.mcpError(w, req, "operation not found: "+args.Handle)
		}
	case "audit_log":
		var args struct {
			Limit int `json:"limit"`
		}
		json.Unmarshal(params.Arguments, &args)
		if args.Limit == 0 {
			args.Limit = 20
		}
		entries := s.store.ListAuditEntries(args.Limit)
		var lines []string
		for _, e := range entries {
			lines = append(lines, fmt.Sprintf("id=%s action=%s actor=%s detail=%s time=%s",
				e.ID, e.Action, e.Actor, e.Detail, e.Timestamp.Format("2006-01-02T15:04:05Z")))
		}
		if len(lines) == 0 {
			s.mcpResult(w, req, "no audit entries")
		} else {
			s.mcpResult(w, req, strings.Join(lines, "\n"))
		}
	default:
		s.mcpError(w, req, "unknown tool: "+params.Name)
	}
}

func (s *Server) mcpEncode(w http.ResponseWriter, req MCPRequest, args json.RawMessage) {
	var params struct {
		Type string `json:"type"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		s.mcpError(w, req, "invalid arguments")
		return
	}
	if !model.IsValidEncoding(params.Type) {
		s.mcpError(w, req, "unsupported encoding type: "+params.Type)
		return
	}
	output, err := Encode(model.EncodingType(params.Type), params.Data)
	if err != nil {
		s.mcpError(w, req, err.Error())
		return
	}
	s.mcpResult(w, req, fmt.Sprintf("type=%s input=%s output=%s", params.Type, params.Data, output))
}

func (s *Server) mcpDecode(w http.ResponseWriter, req MCPRequest, args json.RawMessage) {
	var params struct {
		Type string `json:"type"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		s.mcpError(w, req, "invalid arguments")
		return
	}
	if !model.IsValidEncoding(params.Type) {
		s.mcpError(w, req, "unsupported encoding type: "+params.Type)
		return
	}
	output, err := Decode(model.EncodingType(params.Type), params.Data)
	if err != nil {
		s.mcpError(w, req, err.Error())
		return
	}
	s.mcpResult(w, req, fmt.Sprintf("type=%s input=%s output=%s", params.Type, params.Data, output))
}

func (s *Server) mcpResult(w http.ResponseWriter, req MCPRequest, text string) {
	writeJSON(w, http.StatusOK, MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": text,
				},
			},
		},
	})
}

func (s *Server) mcpError(w http.ResponseWriter, req MCPRequest, msg string) {
	writeJSON(w, http.StatusOK, MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Error:   &MCError{Code: -32603, Message: msg},
	})
}
