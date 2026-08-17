FROM golang:1.26.6-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags '-s -w -X main.version=container' -o /out/tunless ./cmd/tunless

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="tunless Docker namespace controller"
LABEL org.opencontainers.image.source="https://github.com/bojieli/tunless"
COPY --from=build /out/tunless /usr/local/bin/tunless
ENTRYPOINT ["/usr/local/bin/tunless"]
