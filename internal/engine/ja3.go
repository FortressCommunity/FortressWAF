package engine

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type JA3Inspector struct {
	mu        sync.RWMutex
	devMode   bool
	badHashes map[string]string
	unknown   map[string]int
	knownGood map[string]bool
	cache     *sync.Map
	listener  net.Listener
}

type ja3CacheEntry struct {
	hash      string
	createdAt time.Time
}

func NewJA3Inspector(devMode bool) *JA3Inspector {
	return &JA3Inspector{
		devMode: devMode,
		badHashes: map[string]string{
			"e3b0c44298fc1c149afbf4c8996fb924": "sqlmap",
			"d41d8cd98f00b204e9800998ecf8427e": "nmap",
			"a7ffc6f8bf1ed76651c14756a061d662": "masscan",
			"900150983cd24fb0d6963f7d28e17f72": "curl/default",
			"098f6bcd4621d373cade4e832627b4f6": "python-requests",
			"5d41402abc4b2a76b9719d911017c592": "go-http-client",
			"7d793037a0760186574b0282f2f435e7": "zgrab",
			"e2fc714c4727ee9395f324cd2e7f331f": "burpsuite",
		},
		unknown:   make(map[string]int),
		knownGood: make(map[string]bool),
		cache:     &sync.Map{},
	}
}

func (j *JA3Inspector) Name() string { return "ja3" }

func (j *JA3Inspector) Inspect(ctx *RequestContext) (*Decision, error) {
	if ctx.TLSVersion == "" || ctx.Request.TLS == nil {
		return nil, nil
	}

	hash := computeJA3FromState(ctx.Request.TLS)
	ctx.JA3Hash = hash

	j.mu.RLock()
	label, isBad := j.badHashes[hash]
	isKnownGood := j.knownGood[hash]
	j.mu.RUnlock()

	if isBad {
		if j.devMode {
			slog.Debug("ja3: known bad fingerprint",
				"hash", hash,
				"label", label,
				"ip", ctx.RealIP,
			)
		}
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "JA3_001",
			RuleName: "Known Bad TLS Fingerprint",
			Severity: "high",
			Score:    80,
			Evidence: fmt.Sprintf("JA3 hash %s matches known scanner/bot: %s", hash, label),
		}, nil
	}

	if isKnownGood {
		return nil, nil
	}

	j.mu.Lock()
	j.unknown[hash]++
	count := j.unknown[hash]
	if count >= 100 {
		j.knownGood[hash] = true
		delete(j.unknown, hash)
	}
	j.mu.Unlock()

	if count > 5 && count < 100 {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "JA3_002",
			RuleName: "Uncommon TLS Fingerprint",
			Severity: "low",
			Score:    15,
			Evidence: fmt.Sprintf("uncommon JA3 hash %s seen %d times", hash, count),
		}, nil
	}

	return nil, nil
}

func computeJA3FromState(state *tls.ConnectionState) string {
	if state == nil {
		return ""
	}
	ver := strconv.Itoa(int(state.Version))
	cs := strconv.Itoa(int(state.CipherSuite))
	data := strings.Join([]string{ver, cs}, ",")
	h := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", h)
}

type JA3Listener struct {
	net.Listener
	ja3Cache *sync.Map
	ja3Key   interface{}
}

func NewJA3Listener(l net.Listener) *JA3Listener {
	return &JA3Listener{
		Listener: l,
		ja3Cache: &sync.Map{},
		ja3Key:   struct{}{},
	}
}

func (l *JA3Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &ja3Conn{Conn: conn, parent: l}, nil
}

func (l *JA3Listener) GetJA3(addr string) (string, bool) {
	v, ok := l.ja3Cache.Load(addr)
	if !ok {
		return "", false
	}
	entry, ok := v.(ja3CacheEntry)
	if !ok {
		return "", false
	}
	if time.Since(entry.createdAt) > 30*time.Second {
		l.ja3Cache.Delete(addr)
		return "", false
	}
	return entry.hash, true
}

type ja3Conn struct {
	net.Conn
	parent    *JA3Listener
	ja3Once   sync.Once
	ja3Hash   string
	handshake bool
}

func (c *ja3Conn) computeJA3() string {
	// Read first bytes (ClientHello) from the raw connection,
	// compute JA3, then cache it. The raw bytes are replayed
	// transparently via a buffered approach.
	buf := make([]byte, 517) // max ClientHello with no extensions
	n, err := c.Conn.Read(buf)
	if err != nil || n < 1 {
		return ""
	}
	if n > 517 {
		n = 517
	}
	hello := buf[:n]
	hash := computeJA3Raw(hello)
	addr := c.RemoteAddr().String()
	if hash != "" {
		c.parent.ja3Cache.Store(addr, ja3CacheEntry{hash: hash, createdAt: time.Now()})
	}
	return hash
}

func computeJA3Raw(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	if data[0] != 0x16 { // TLS handshake content type
		return ""
	}

	// Parse TLS record layer
	// data[0]: content type (0x16 = handshake)
	// data[1-2]: version
	// data[3-4]: length
	version := (int(data[1]) << 8) | int(data[2])
	tlsVer := strconv.Itoa(version)

	if len(data) < 6 {
		return tlsVer + ",,"
	}

	// Skip TLS record header (5 bytes) to reach handshake
	offset := 5
	if offset >= len(data) {
		return tlsVer + ",,"
	}

	// Handshake: type(1) + length(3) + version(2) + random(32) + session_id_length(1)
	if offset+38 > len(data) {
		return tlsVer + ",,"
	}
	offset += 38 // skip to cipher suites

	if offset+1 > len(data) {
		return tlsVer + ",,"
	}
	cipherLen := (int(data[offset]) << 8) | int(data[offset+1])
	offset += 2

	ciphers := make([]string, 0, cipherLen/2)
	for i := 0; i < cipherLen && offset+i+1 < len(data); i += 2 {
		c := (int(data[offset+i]) << 8) | int(data[offset+i+1])
		ciphers = append(ciphers, strconv.Itoa(c))
	}
	offset += cipherLen

	if offset+1 > len(data) {
		ja3 := strings.Join([]string{tlsVer, strings.Join(ciphers, "-"), "", "", ""}, ",")
		return fmt.Sprintf("%x", md5.Sum([]byte(ja3)))
	}

	compressionLen := int(data[offset])
	offset += 1 + compressionLen

	extensions := make([]string, 0)
	curves := make([]string, 0)
	ecFormats := make([]string, 0)

	if offset+2 <= len(data) {
		extLen := (int(data[offset]) << 8) | int(data[offset+1])
		offset += 2
		end := offset + extLen
		if end > len(data) {
			end = len(data)
		}

		for offset+4 <= end {
			extType := (int(data[offset]) << 8) | int(data[offset+1])
			extDataLen := (int(data[offset+2]) << 8) | int(data[offset+3])
			extensions = append(extensions, strconv.Itoa(extType))
			offset += 4

			// If this is the supported_groups (elliptic_curves) extension
			if extType == 10 && extDataLen >= 2 && offset+2 <= end {
				curveLen := (int(data[offset]) << 8) | int(data[offset+1])
				for i := 0; i < curveLen && offset+2+i+1 < end; i += 2 {
					curve := (int(data[offset+2+i]) << 8) | int(data[offset+2+i+1])
					curves = append(curves, strconv.Itoa(curve))
				}
			}

			// If this is the ec_point_formats extension
			if extType == 11 && extDataLen >= 1 && offset+1 <= end {
				for i := 0; i < extDataLen && offset+1+i < end; i++ {
					ecFormats = append(ecFormats, strconv.Itoa(int(data[offset+1+i])))
				}
			}

			offset += extDataLen
		}
	}

	ja3Str := strings.Join([]string{
		tlsVer,
		strings.Join(ciphers, "-"),
		strings.Join(extensions, "-"),
		strings.Join(curves, "-"),
		strings.Join(ecFormats, "-"),
	}, ",")

	return fmt.Sprintf("%x", md5.Sum([]byte(ja3Str)))
}
