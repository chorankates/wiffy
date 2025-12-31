FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 go build -o wiffy .

# Final stage
FROM alpine:latest

# Install nmap and ca-certificates
RUN apk add --no-cache nmap ca-certificates

WORKDIR /app

# Copy binary and static files from builder
COPY --from=builder /app/wiffy .
COPY --from=builder /app/static ./static

# Create directory for database
RUN mkdir -p /data

ENV WIFFY_DB_PATH=/data/wiffy.db
ENV PORT=8080

EXPOSE 8080

CMD ["./wiffy"]

