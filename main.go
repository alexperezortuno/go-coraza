package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/oschwald/geoip2-golang"
	"golang.org/x/time/rate"
)

type Backend struct {
	Addrs   []string
	Counter uint64
}

// IPRateLimiter manage the rate limit for IP
type IPRateLimiter struct {
	ips map[string]*visitor
	mu  sync.Mutex
	r   rate.Limit
	b   int
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var geoDB *geoip2.Reader
var geoBlockEnabled bool
var blockBots bool
var geoAllow map[string]struct{}
var geoBlock map[string]struct{}

// NewIPRateLimiter creates and initializes a new IPRateLimiter with the specified rate limit and burst size.
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	i := &IPRateLimiter{
		ips: make(map[string]*visitor),
		r:   r,
		b:   b,
	}
	go i.cleanupVisitors()
	return i
}

// GetLimiter returns a rate limiter for the specified IP address, creating a new one if it does not exist,
// and updates its last seen time.
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	v, exists := i.ips[ip]
	if !exists {
		limiter := rate.NewLimiter(i.r, i.b)
		i.ips[ip] = &visitor{limiter, time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

// cleanupVisitors removes inactive visitors from the IP map based on the configured inactivity duration.
func (i *IPRateLimiter) cleanupVisitors() {
	for {
		time.Sleep(time.Minute)
		i.mu.Lock()
		for ip, v := range i.ips {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(i.ips, ip)
			}
		}
		i.mu.Unlock()
	}
}

// loadBackendsFromEnv loads backend configurations from the "BACKENDS" environment variable or assigns a default backend.
func loadBackendsFromEnv() (map[string]*Backend, error) {
	raw := os.Getenv("BACKENDS")
	if strings.TrimSpace(raw) == "" {
		return map[string]*Backend{
			"default": {Addrs: []string{"localhost:5000"}},
		}, nil
	}

	var parsed map[string][]string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, err
	}

	result := make(map[string]*Backend, len(parsed))
	for host, addrs := range parsed {
		result[host] = &Backend{Addrs: addrs}
	}
	return result, nil
}

// shouldBlock determines if a request should be blocked based on the given interruption's status code.
// If the interruption is nil or the status code is less than 400, it returns false with status 0.
// Otherwise, it returns true with the provided status code.
func shouldBlock(it *ctypes.Interruption) (bool, int) {
	if it == nil {
		return false, 0
	}
	if it.Status < 400 {
		return false, 0
	}
	return true, it.Status
}

// getPort retrieves the port number from the "PORT" environment variable or defaults to "8081" if not set or invalid.
func getPort() string {
	port := os.Getenv("PORT")
	if port == "" {
		return "8081"
	}
	if _, err := strconv.Atoi(port); err != nil {
		log.Printf("Invalid PORT, using 8081")
		return "8081"
	}
	return port
}

// splitHostPort extracts the host and port from a network address string. Defaults to port 80 if not specified.
func splitHostPort(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err == nil {
		port, _ := strconv.Atoi(portStr)
		return host, port
	}

	// No puerto → usar default
	return addr, 80
}

// parseHosts retrieves a comma-separated list of hosts from the specified environment variable and returns them as a map.
func parseHosts(envVar string) map[string]struct{} {
	raw := os.Getenv(envVar)
	result := make(map[string]struct{})
	for _, h := range strings.Split(raw, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			result[h] = struct{}{}
		}
	}
	return result
}

// loadWAF loads a Web Application Firewall (WAF) configuration from a colon-separated list of file paths.
func loadWAF(paths string) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig()
	for _, f := range strings.Split(paths, ":") {
		f = strings.TrimSpace(f)
		if f != "" {
			cfg = cfg.WithDirectivesFromFile(f)
		}
	}
	return coraza.NewWAF(cfg)
}

// getEnvString returns the value of the specified environment variable or an empty string if it is not set.
func getEnvString(key string, d string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return d
}

// getEnvInt returns the value of the specified environment variable as an integer or 0 if it is not set or invalid.
func getEnvInt(key string, d int) int {
	if value, err := strconv.Atoi(getEnvString(key, "")); err == nil {
		return value
	}
	return d
}

func getEnvBool(key string, d bool) bool {
	if value, err := strconv.ParseBool(getEnvString(key, "")); err == nil {
		return value
	}
	return d
}

// realClientIP extracts the client's real IP address from HTTP headers or the remote address.
// It checks headers "CF-Connecting-IP" and "X-Forwarded-For" for proxy configurations.
func realClientIP(r *http.Request) string {
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		return cf
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		// primer IP del XFF
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _ := splitHostPort(r.RemoteAddr)
	return host
}

func loadGeoIP(path string) {
	var err error
	geoDB, err = geoip2.Open(path)
	if err != nil {
		log.Fatalf("GeoIP DB error: %v", err)
	}
	log.Println("GeoIP database loaded")
}

func getCountryCode(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP")
	}
	record, err := geoDB.Country(ip)
	if err != nil {
		return "", err
	}
	return record.Country.IsoCode, nil
}

func parseCSVSet(env string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, c := range strings.Split(env, ",") {
		c = strings.TrimSpace(strings.ToUpper(c))
		if c != "" {
			out[c] = struct{}{}
		}
	}
	return out
}

func geoFilter(r *http.Request, allow, block map[string]struct{}) (bool, string) {
	ip, _ := splitHostPort(r.RemoteAddr)

	country, err := getCountryCode(ip)
	if err != nil {
		return false, "geo lookup failed"
	}

	if _, blocked := block[country]; blocked {
		return false, "geo blocked"
	}

	if len(allow) > 0 {
		if _, ok := allow[country]; !ok {
			return false, "geo not allowed"
		}
	}

	return true, country
}

func start() {
	// Create directories
	err := os.MkdirAll("/tmp/log/coraza", 0755)
	if err != nil {
		return
	}
	// Create empty files
	_, err = os.Create("/tmp/log/coraza/audit.log")
	if err != nil {
		return
	}

	err = os.Chmod("/tmp/log/coraza/audit.log", 0644)
	if err != nil {
		return
	}

	_, err = os.Create("/tmp/log/coraza/debug.log")
	if err != nil {
		return
	}

	err = os.Chmod("/tmp/log/coraza/debug.log", 0644)
	if err != nil {
		return
	}

	geoBlockEnabled = getEnvBool("GEO_BLOCK_ENABLED", false)
	if geoBlockEnabled {
		loadGeoIP("/app/GeoLite2-Country.mmdb")
	}

	blockBots = getEnvBool("PROXY_BLOCK_BOTS", false)
}

func main() {
	start()
	// ------------ RULES FOR SITES (PL1) ------------
	rulesSites := os.Getenv("CORAZA_RULES_PATH_SITES")
	if rulesSites == "" {
		rulesSites = "/app/coraza.conf:/app/coreruleset/pl1-crs-setup.conf:/app/coreruleset/rules/*.conf"
	}

	// ------------ RULES FOR SITES (PL2) ------------
	rulesAPIs := os.Getenv("CORAZA_RULES_PATH_APIS")
	if rulesAPIs == "" {
		rulesAPIs = "/app/coraza.conf:/app/coreruleset/pl2-crs-setup.conf:/app/coreruleset/rules/REQUEST-901-INITIALIZATION.conf:/app/coreruleset/rules/*.conf"
	}

	// Load backends
	backends, err := loadBackendsFromEnv()
	if err != nil {
		log.Fatalf("Error parsing BACKENDS: %v", err)
	}

	// Load WAFs
	wafSites, err := loadWAF(rulesSites)
	if err != nil {
		log.Fatalf("Error creating WAF sites: %v", err)
	}

	wafApis, err := loadWAF(rulesAPIs)
	if err != nil {
		log.Fatalf("Error creating WAF APIs: %v", err)
	}

	apisHosts := parseHosts("PROXY_APIS_HOSTS")
	webHosts := parseHosts("PROXY_WEB_HOSTS")

	limiter := NewIPRateLimiter(
		rate.Limit(getEnvInt("PROXY_RATE_LIMIT", 5)),
		getEnvInt("PROXY_RATE_BURST", 10),
	)

	if geoBlockEnabled {
		geoAllow = parseCSVSet(os.Getenv("GEO_ALLOW_COUNTRIES"))
		geoBlock = parseCSVSet(os.Getenv("GEO_BLOCK_COUNTRIES"))
	}

	log.Println("Coraza WAF started")

	// ------------------------ HANDLER ------------------------
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if geoBlockEnabled {
			allowed, country := geoFilter(r, geoAllow, geoBlock)
			if !allowed {
				log.Printf("[GEO] blocked %s from %s", r.RemoteAddr, country)
				http.Error(w, "Access denied by GeoIP policy", http.StatusForbidden)
				return
			}
		}

		clientIP := realClientIP(r)

		if !limiter.GetLimiter(clientIP).Allow() {
			log.Println("Too Many Requests - IP blocked", clientIP)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		if blockBots {
			ua := strings.ToLower(r.UserAgent())
			envBots := getEnvString("PROXY_BOTS", "python,googlebot,bingbot,yandex,baiduspider")
			badBots := strings.Split(envBots, ",")
			for _, bot := range badBots {
				if strings.Contains(ua, bot) {
					log.Println("Bot blocked", clientIP)
					http.Error(w, "Bot blocked", http.StatusForbidden)
					return
				}
			}
		}

		hostOnly := strings.Split(r.Host, ":")[0]
		var waf coraza.WAF

		if _, ok := apisHosts[hostOnly]; ok {
			waf = wafApis
		}

		if _, ok := webHosts[hostOnly]; ok {
			waf = wafSites
		}

		tx := waf.NewTransaction()
		defer tx.ProcessLogging()
		defer func(tx ctypes.Transaction) {
			err := tx.Close()
			if err != nil {
				log.Println("Error closing WAF transaction:", err)
			}
		}(tx)

		// Connection
		_, clientPort := splitHostPort(r.RemoteAddr)
		serverIP, serverPort := splitHostPort(r.Host)
		tx.ProcessConnection(clientIP, clientPort, serverIP, serverPort)

		// Headers
		for k, v := range r.Header {
			for _, vv := range v {
				tx.AddRequestHeader(k, vv)
			}
		}
		tx.ProcessURI(r.URL.String(), r.Method, r.Proto)

		if it := tx.ProcessRequestHeaders(); it != nil {
			if block, status := shouldBlock(it); block {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("Request blocked by WAF (headers)"))
				log.Println("Request blocked by WAF (headers)")
				return
			}
		}

		// Body
		if r.Body != nil && (r.ContentLength > 0 || r.Header.Get("Transfer-Encoding") != "") {
			body, err := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if err != nil {
				log.Println("Error reading body:", err)
				http.Error(w, "Error reading body", http.StatusBadRequest)
				return
			}

			if len(body) > 0 {
				_, _, err = tx.WriteRequestBody(body)
				if err != nil {
					log.Println("Error processing body:", err)
					http.Error(w, "Error processing body", http.StatusBadRequest)
					return
				}

				if it, _ := tx.ProcessRequestBody(); it != nil {
					w.WriteHeader(it.Status)
					_, _ = w.Write([]byte("Request blocked by WAF (body)"))
					log.Println("Request blocked by WAF (body)")
					return
				}

				r.Body = io.NopCloser(bytes.NewReader(body))
				r.ContentLength = int64(len(body))
				r.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
			}
		}

		// Backend
		be, ok := backends[hostOnly]
		if !ok {
			be = backends["default"]
		}
		idx := int((atomic.AddUint64(&be.Counter, 1) - 1) % uint64(len(be.Addrs)))
		target := be.Addrs[idx]

		outReq := r.Clone(r.Context())
		outReq.URL.Scheme = "http"
		outReq.URL.Host = target
		outReq.RequestURI = ""
		outReq.Host = hostOnly

		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, "Bad Gateway: "+err.Error(), 502)
			return
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				log.Println("Error closing backend response body:", err)
			}
		}(resp.Body)

		for k, v := range resp.Header {
			for _, vv := range v {
				tx.AddResponseHeader(k, vv)
				w.Header().Add(k, vv)
			}
		}

		if it := tx.ProcessResponseHeaders(resp.StatusCode, resp.Proto); it != nil {
			if block, status := shouldBlock(it); block {
				w.WriteHeader(status)
				_, err := w.Write([]byte("Response blocked by WAF"))
				if err != nil {
					return
				}
				return
			}
		}

		w.WriteHeader(resp.StatusCode)
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			return
		}
	})

	port := ":" + getPort()
	log.Println("Listening on ", port)
	log.Fatal(http.ListenAndServe(port, handler))
}
