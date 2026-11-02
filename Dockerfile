# nd-check as a container: scheduled proxy-pool refreshes on any server.
FROM rust:1-alpine AS build
WORKDIR /src
COPY Cargo.toml ./
COPY core ./core
COPY cli ./cli
RUN cargo build --release --bin nd-check

FROM alpine:3.20
RUN adduser -D nd
COPY --from=build /src/target/release/nd-check /usr/local/bin/nd-check
USER nd
ENTRYPOINT ["nd-check"]
CMD ["--help"]
