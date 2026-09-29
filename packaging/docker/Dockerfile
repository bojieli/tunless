FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build
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
