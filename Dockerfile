# Stage 1: Build the control-plane binary
FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/control-plane ./cmd/control-plane

# Stage 2: Minimal runtime image
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /bin/control-plane /usr/local/bin/control-plane

USER 65534

ENTRYPOINT ["control-plane"]
