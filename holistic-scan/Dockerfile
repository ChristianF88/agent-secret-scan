# holistic-scan: agent-secret-scan, Betterleaks and TruffleHog in one image.
# Build from the repository root (the holistic-scan script does this):
#   docker build -f holistic-scan/Dockerfile -t holistic-scan .

# agent-secret-scan, built from this repository.
FROM debian:trixie-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY rust-toolchain.toml ./
RUN curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none \
 && /root/.cargo/bin/rustup toolchain install "$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)" --profile minimal
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY spec spec
RUN /root/.cargo/bin/cargo build --profile dist --locked -p agent-secret-scan

# Betterleaks and TruffleHog release binaries, checked against pinned SHA-256 sums.
FROM debian:trixie-slim AS tools
ARG TARGETARCH
ARG BETTERLEAKS_VERSION=1.10.0
ARG TRUFFLEHOG_VERSION=3.99.8
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) bl=x64; th=amd64; \
             bl_sum=9d9ad503cd5d80d18a939352266c3fcca52f10da9b83cd5cfe646989b13940fe; \
             th_sum=7c3b02f160f28929a467e29e20fba98746e0729f6e37c3c25761e4f8789abe08 ;; \
      arm64) bl=arm64; th=arm64; \
             bl_sum=3d7585cbe4f947aef6e31662f65beb5b43b104381a691b6b81b157ebfbb0c02d; \
             th_sum=a0382d83dd58c967af5dd0175cc732c62c836ab1d15dc9ae71b01a2d3f0911b2 ;; \
      *) echo "unsupported architecture: ${TARGETARCH:-unknown}" >&2; exit 1 ;; \
    esac; \
    bl_tar="betterleaks_${BETTERLEAKS_VERSION}_linux_${bl}.tar.gz"; \
    th_tar="trufflehog_${TRUFFLEHOG_VERSION}_linux_${th}.tar.gz"; \
    curl -sSfLO "https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/${bl_tar}"; \
    curl -sSfLO "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/${th_tar}"; \
    echo "${bl_sum}  ${bl_tar}" | sha256sum -c -; \
    echo "${th_sum}  ${th_tar}" | sha256sum -c -; \
    tar -xzf "${bl_tar}" betterleaks; \
    tar -xzf "${th_tar}" trufflehog

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git jq \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/dist/agent-secret-scan /usr/local/bin/
COPY --from=tools /dl/betterleaks /dl/trufflehog /usr/local/bin/
COPY holistic-scan/scan.sh /usr/local/bin/holistic-scan-run
ENTRYPOINT ["holistic-scan-run"]
