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
	"sync/atomic"

	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
)

type Backend struct {
	Addrs   []string
	Counter uint64
}

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

func shouldBlock(it *ctypes.Interruption) (bool, int) {
	if it == nil {
		return false, 0
	}
	if it.Status < 400 {
		return false, 0
	}
	return true, it.Status
}

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

func splitHostPort(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err == nil {
		port, _ := strconv.Atoi(portStr)
		return host, port
	}

	// No puerto → usar default
	return addr, 80
}

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

func main() {

	// ------------ REGLAS PARA SITIOS (PL1) ------------
	rulesSites := os.Getenv("CORAZA_RULES_PATH_SITES")
	if rulesSites == "" {
		rulesSites = "/app/coraza.conf:/app/coreruleset/pl1-crs-setup.conf:/app/coreruleset/rules/*.conf"
	}

	// ------------ REGLAS PARA APIS (PL2) ------------
	rulesAPIs := os.Getenv("CORAZA_RULES_PATH_APIS")
	if rulesAPIs == "" {
		rulesAPIs = "/app/coraza.conf:/app/coreruleset/pl2-crs-setup.conf:/app/coreruleset/rules/REQUEST-901-INITIALIZATION.conf:/app/coreruleset/rules/*.conf"
	}

	// Cargar backends
	backends, err := loadBackendsFromEnv()
	if err != nil {
		log.Fatalf("Error parsing BACKENDS: %v", err)
	}

	// Crear WAFs
	wafSites, err := loadWAF(rulesSites)
	if err != nil {
		log.Fatalf("Error creando WAF sitios: %v", err)
	}

	wafApis, err := loadWAF(rulesAPIs)
	if err != nil {
		log.Fatalf("Error creando WAF APIs: %v", err)
	}

	apisHosts := parseHosts("WAF_APIS_HOSTS")
	webHosts := parseHosts("WAF_WEB_HOSTS")

	log.Println("Coraza WAF iniciado")

	// ------------------------ HANDLER ------------------------
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

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
		clientIP, clientPort := splitHostPort(r.RemoteAddr)
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
				_, err := w.Write([]byte("Request blocked by WAF (headers)"))
				if err != nil {
					log.Println("Error writing response:", err)
					return
				}
				return
			}
		}

		// Body
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Error reading body", 400)
				return
			}
			err = r.Body.Close()
			if err != nil {
				return
			}

			_, _, err = tx.WriteRequestBody(body)
			if err != nil {
				http.Error(w, "Error processing body", 400)
				return
			}

			if it, _ := tx.ProcessRequestBody(); it != nil {
				w.WriteHeader(it.Status)
				_, err := w.Write([]byte("Request blocked by WAF (body)"))
				if err != nil {
					return
				}
				return
			}

			r.Body = io.NopCloser(bytes.NewBuffer(body))
			r.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
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
