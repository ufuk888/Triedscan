FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o triedscan ./cmd/triedscan

FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y nmap rustscan && rm -rf /var/lib/apt/lists/*
WORKDIR /root/
COPY --from=builder /app/triedscan .
COPY --from=builder /app/web ./web
EXPOSE 8080
CMD ["./triedscan"]
