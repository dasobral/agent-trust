# att-node image built from source (CI, or any machine with registry access).
#   docker build -f deploy/docker/Dockerfile -t agent-trust-testbed/att-node:local .
# The build fetches the pinned agent-trust, OpenMLS fork and openmls-qrand from GitHub.
ARG RUST_IMAGE=rust:1.91-bookworm
ARG BASE_IMAGE=ubuntu:24.04

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --release --locked -p att-node

FROM ${BASE_IMAGE}
RUN useradd --system --uid 10001 --home-dir /var/lib/att att \
 && mkdir -p /var/lib/att/apf /var/lib/att/agent && chown -R att /var/lib/att
COPY --from=build /src/target/release/att-node /usr/local/bin/att-node
USER att
ENTRYPOINT ["att-node"]
