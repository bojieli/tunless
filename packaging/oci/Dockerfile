ARG SOURCE_DATE_EPOCH=0
FROM release AS artifacts

FROM scratch
ARG TARGETARCH
ARG VERSION=container
LABEL org.opencontainers.image.title="tunless Docker namespace controller"
LABEL org.opencontainers.image.source="https://github.com/bojieli/tunless"
LABEL org.opencontainers.image.version="$VERSION"
LABEL org.opencontainers.image.licenses="MIT"
COPY --from=artifacts /tunless_${VERSION}_linux_${TARGETARCH} /usr/local/bin/tunless
ENTRYPOINT ["/usr/local/bin/tunless"]
