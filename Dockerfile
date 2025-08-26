# Multi-stage build for minimal production image
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o authguard ./cmd/authguard

# Production stage
FROM alpine:latest

# Install ca-certificates and curl for health checks
RUN apk --no-cache add ca-certificates curl

# Create non-root user
RUN addgroup -g 1001 -S authguard && \
    adduser -u 1001 -S authguard -G authguard

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/authguard .

# Change ownership to non-root user
RUN chown authguard:authguard /app/authguard

# Switch to non-root user
USER authguard

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the binary
ENTRYPOINT ["./authguard"]
