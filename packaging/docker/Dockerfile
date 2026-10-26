FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
ARG VERSION=container
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X main.version=${VERSION}" \
    -o /out/tunless ./cmd/tunless

FROM scratch
ARG VERSION=container
LABEL org.opencontainers.image.title="tunless Docker namespace controller"
LABEL org.opencontainers.image.source="https://github.com/bojieli/tunless"
LABEL org.opencontainers.image.version="$VERSION"
COPY --from=build /out/tunless /usr/local/bin/tunless
ENTRYPOINT ["/usr/local/bin/tunless"]
