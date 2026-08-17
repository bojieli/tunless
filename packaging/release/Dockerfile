FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36

ARG TARGETARCH
ARG NFPM_VERSION=2.47.0
ARG SYFT_VERSION=1.51.0

RUN apt-get update && apt-get install --yes --no-install-recommends \
      ca-certificates curl gettext-base git gzip rpm xz-utils zstd \
    && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
         amd64) nfpm_arch=x86_64; nfpm_sha=0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783; syft_sha=2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f ;; \
         arm64) nfpm_arch=arm64; nfpm_sha=1c0f5f2999b9a974bfb04fdb0cc3306096de530ac5dbb25d739cc5f5219c919c; syft_sha=6c0466811541ea03add5213a60a1562f0851e4c0b0ecfdee1a694a9455285900 ;; \
         *) echo "unsupported release-builder architecture: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && curl --fail --http1.1 --location --retry 5 --retry-all-errors \
         --retry-delay 2 --output /tmp/nfpm.tar.gz \
         "https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_${nfpm_arch}.tar.gz" \
    && echo "$nfpm_sha  /tmp/nfpm.tar.gz" | sha256sum --check - \
    && tar -xzf /tmp/nfpm.tar.gz -C /usr/local/bin nfpm \
    && curl --fail --http1.1 --location --retry 5 --retry-all-errors \
         --retry-delay 2 --output /tmp/syft.tar.gz \
         "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && echo "$syft_sha  /tmp/syft.tar.gz" | sha256sum --check - \
    && tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft \
    && rm -f /tmp/nfpm.tar.gz /tmp/syft.tar.gz

WORKDIR /src
ENTRYPOINT ["/src/scripts/build-release.sh"]
