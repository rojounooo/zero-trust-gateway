# ---------- builder ----------
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git build-base

WORKDIR /src

RUN git clone --depth 1 \
    https://github.com/open-policy-agent/opa-envoy-plugin.git .

RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w" \
    -o /opa \
    ./cmd/opa-envoy-plugin


# ---------- runtime ----------
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /opa /opa

ENTRYPOINT ["/opa"]
