package store

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/relentlessworks/encodekit/internal/model"
)

// Store manages persisted data using a JSON file.
type Store struct {
	mu       sync.RWMutex
	filePath string
	data     *storeData
}

type storeData struct {
	Workspaces map[string]*model.Workspace `json:"workspaces"`
	Operations map[string]*model.Operation `json:"operations"`
	AuditLog   []model.AuditEntry          `json:"audit_log"`
}

// New creates a new store. If filePath is empty, uses in-memory only.
func New(filePath string) *Store {
	s := &Store{
		filePath: filePath,
		data: &storeData{
			Workspaces: make(map[string]*model.Workspace),
			Operations: make(map[string]*model.Operation),
			AuditLog:   []model.AuditEntry{},
		},
	}
	if filePath != "" {
		s.load()
	}
	return s
}

func (s *Store) load() {
	b, err := os.ReadFile(s.filePath)
	if err != nil {
		return
	}
	var d storeData
	if err := json.Unmarshal(b, &d); err != nil {
		return
	}
	if d.Workspaces == nil {
		d.Workspaces = make(map[string]*model.Workspace)
	}
	if d.Operations == nil {
		d.Operations = make(map[string]*model.Operation)
	}
	if d.AuditLog == nil {
		d.AuditLog = []model.AuditEntry{}
	}
	s.data = &d
}

func (s *Store) save() {
	if s.filePath == "" {
		return
	}
	s.mu.RLock()
	b, err := json.MarshalIndent(s.data, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return
	}
	os.WriteFile(s.filePath, b, 0644)
}

// SaveOperation stores an encoding/decode operation.
func (s *Store) SaveOperation(op *model.Operation) {
	s.mu.Lock()
	s.data.Operations[op.Handle] = op
	s.mu.Unlock()
	s.save()
}

// GetOperation retrieves an operation by handle.
func (s *Store) GetOperation(handle string) (*model.Operation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	op, ok := s.data.Operations[handle]
	return op, ok
}

// ListOperations returns all operations.
func (s *Store) ListOperations() []*model.Operation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ops := make([]*model.Operation, 0, len(s.data.Operations))
	for _, op := range s.data.Operations {
		ops = append(ops, op)
	}
	return ops
}

// DeleteOperation removes an operation by handle.
func (s *Store) DeleteOperation(handle string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Operations[handle]; ok {
		delete(s.data.Operations, handle)
		s.save()
		return true
	}
	return false
}

// AddAuditEntry records an audit log entry.
func (s *Store) AddAuditEntry(entry model.AuditEntry) {
	s.mu.Lock()
	s.data.AuditLog = append(s.data.AuditLog, entry)
	s.mu.Unlock()
	s.save()
}

// ListAuditEntries returns recent audit entries.
func (s *Store) ListAuditEntries(limit int) []model.AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.data.AuditLog) {
		limit = len(s.data.AuditLog)
	}
	start := len(s.data.AuditLog) - limit
	if start < 0 {
		start = 0
	}
	result := make([]model.AuditEntry, limit)
	copy(result, s.data.AuditLog[start:])
	return result
}

// NewAuditEntry creates a new audit entry with a generated ID.
func NewAuditEntry(action, actor, detail string) model.AuditEntry {
	return model.AuditEntry{
		ID:        model.GenerateHandle("aud"),
		Action:    action,
		Actor:     actor,
		Detail:    detail,
		Timestamp: time.Now(),
	}
}
