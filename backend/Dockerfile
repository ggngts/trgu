# syntax=docker/dockerfile:1.7

FROM golang:1.25-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/traffic-guardian ./cmd/server

FROM debian:bookworm-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get install -y --no-install-recommends \
      tshark \
      ca-certificates \
      tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin guardian \
 && mkdir -p /tmp/traffic-guardian \
 && chown -R guardian:guardian /app /tmp/traffic-guardian

COPY --from=build --chown=guardian:guardian /out/traffic-guardian /app/traffic-guardian

USER guardian
WORKDIR /app

EXPOSE 5444
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/traffic-guardian"]
