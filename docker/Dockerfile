FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git
WORKDIR /app

# Descargar Coraza y OWASP CRS
RUN git clone --depth 1 https://github.com/coreruleset/coreruleset

COPY .. .

RUN go mod tidy
RUN go build -o /coraza-proxy main.go

FROM alpine:latest

RUN mkdir /app
COPY --from=builder /coraza-proxy /app/coraza-proxy
COPY ../profiles/coraza.conf /app/coraza.conf
COPY --from=builder /app/coreruleset/rules /app/coreruleset/rules
COPY ../profiles/pl1-crs-setup.conf /app/coreruleset/pl1-crs-setup.conf
COPY ../profiles/pl2-crs-setup.conf /app/coreruleset/pl2-crs-setup.conf
RUN mkdir -p /var/log/coraza
RUN touch /var/log/coraza/audit.log

EXPOSE 8081
ENTRYPOINT ["/app/coraza-proxy"]
