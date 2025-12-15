FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git
WORKDIR /src

COPY . .

RUN go mod tidy
# Descargar Coraza y OWASP CRS
RUN git clone --depth 1 https://github.com/coreruleset/coreruleset /src/coreruleset
RUN go build -o /coraza-proxy main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app

COPY --from=builder /coraza-proxy /app/coraza-proxy
COPY --from=builder /src/coreruleset /app/coreruleset
COPY --from=builder /src/profiles /app/profiles
COPY --from=builder /src/coreruleset/crs-setup.conf.example /app/profiles/crs-setup.conf

RUN mkdir -p /var/log/coraza && touch /var/log/coraza/audit.log

ENTRYPOINT ["/app/coraza-proxy"]
