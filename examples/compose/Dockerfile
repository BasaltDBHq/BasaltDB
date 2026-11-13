# One image for both containers of the example: the engine container runs it
# as root under tini and basalt engine --user drops to basalt; the agent
# container runs it as agent. Build context: the repository root.
ARG GO_VERSION=1.26.0

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 like the release builds: basalt engine --user needs it to
# set no_new_privs on every thread.
RUN CGO_ENABLED=0 go build -trimpath -o /out/basalt ./cmd/basalt

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# basalt is the engine's OS user, agent the agent's. The agent's uid must be
# the same in both containers: the engine checks it on the shared socket.
RUN useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin basalt \
 && useradd --uid 1001 --user-group --create-home --shell /bin/sh agent \
 && install -d -o basalt -g basalt -m 0750 /etc/basalt
# Root-owned, in a root-owned directory: basalt engine --user refuses a binary
# anyone but root could change.
COPY --from=build --chown=root:root --chmod=0755 /out/basalt /usr/local/libexec/basalt
RUN ln -s /usr/local/libexec/basalt /usr/local/bin/basalt
ENTRYPOINT ["/usr/bin/tini", "--"]
