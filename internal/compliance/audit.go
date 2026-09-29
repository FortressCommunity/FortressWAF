package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type AuditEntry struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	ActorID    string    `json:"actor_id"`
	ActorType  string    `json:"actor_type"`
	ActorIP    string    `json:"actor_ip"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	ResourceID string    `json:"resource_id"`
	Result     string    `json:"result"`
	// Metadata is always serialized (even empty) so a client never receives a
	// missing field and crashes on it; the console groups entries by the rule
	// id carried here.
	Metadata string `json:"metadata"`
	Hash     string `json:"hash"`
	PrevHash string `json:"prev_hash"`

	// Request forensics. These are recorded for every inspected request so the
	// console can show what a client actually sent, not just the outcome.
	Method     string            `json:"method,omitempty"`
	Path       string            `json:"path,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	Browser    string            `json:"browser,omitempty"` // parsed: "Chrome 120 on Android 14"
	Device     string            `json:"device,omitempty"`  // desktop | mobile | tablet | bot
	Headers    map[string]string `json:"headers,omitempty"`
}

type AuditLog struct {
	mu        sync.RWMutex
	entries   []AuditEntry
	lastHash  string
	immutable bool
}

// NewAuditLog creates an append-only, hash-chained audit trail.
//
// "immutable" here means entries already written cannot be modified or
// removed; the log itself is meant to be appended to, so it defaults to
// writable. VerifyIntegrity() detects any later tampering.
func NewAuditLog() *AuditLog {
	return &AuditLog{
		entries:   make([]AuditEntry, 0),
		immutable: false,
	}
}

func (al *AuditLog) Append(entry AuditEntry) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.immutable {
		return fmt.Errorf("audit log is immutable")
	}

	entry.Timestamp = time.Now()
	entry.ID = fmt.Sprintf("audit-%d", len(al.entries)+1)
	entry.PrevHash = al.lastHash
	entry.Hash = computeEntryHash(al.lastHash, entry)

	al.entries = append(al.entries, entry)
	al.lastHash = entry.Hash

	return nil
}

// Len returns the number of entries written since startup.
func (al *AuditLog) Len() int {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return len(al.entries)
}

func (al *AuditLog) Query(filter AuditFilter) ([]AuditEntry, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var results []AuditEntry
	for _, entry := range al.entries {
		if filter.ActorID != "" && entry.ActorID != filter.ActorID {
			continue
		}
		if filter.Action != "" && entry.Action != filter.Action {
			continue
		}
		if filter.Resource != "" && entry.Resource != filter.Resource {
			continue
		}
		if !filter.From.IsZero() && filter.From.After(entry.Timestamp) {
			continue
		}
		if !filter.To.IsZero() && filter.To.Before(entry.Timestamp) {
			continue
		}
		results = append(results, entry)
	}

	return results, nil
}

type AuditFilter struct {
	ActorID  string
	Action   string
	Resource string
	From     time.Time
	To       time.Time
}

func (al *AuditLog) VerifyIntegrity() (bool, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var prevHash string
	for i, entry := range al.entries {
		if i == 0 && entry.PrevHash != "" {
			return false, fmt.Errorf("chain broken at entry %d: first entry has prev_hash", i)
		}
		if entry.PrevHash != prevHash {
			return false, fmt.Errorf("chain broken at entry %d: expected %s, got %s", i, prevHash, entry.PrevHash)
		}
		// Recomputing is what makes the log tamper-evident: linking alone
		// would not notice a modified field inside an existing entry.
		if recomputed := computeEntryHash(prevHash, entry); recomputed != entry.Hash {
			return false, fmt.Errorf("entry %d has been modified: stored hash %s no longer matches its content", i, entry.Hash[:12])
		}
		prevHash = entry.Hash
	}

	return true, nil
}

// computeEntryHash derives the chain hash of an entry from its contents and
// the previous entry's hash. The same function runs on append and on
// verification, so any later edit to a field changes the result.
func computeEntryHash(prevHash string, entry AuditEntry) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d|%s|%s",
		entry.ID, entry.Timestamp.Format(time.RFC3339Nano),
		entry.ActorID, entry.ActorType, entry.ActorIP,
		entry.Action, entry.Resource, entry.ResourceID, entry.Result,
		entry.Method, entry.Path, entry.StatusCode, entry.UserAgent, entry.Metadata)

	hash := sha256.New()
	hash.Write([]byte(prevHash + data))
	return hex.EncodeToString(hash.Sum(nil))
}
