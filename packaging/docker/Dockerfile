FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
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
