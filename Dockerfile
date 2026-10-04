FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
ENV CARGO_BUILD_JOBS=1
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/tapscript-weak-finder /usr/local/bin/tapscript-weak-finder
EXPOSE 8787
ENTRYPOINT ["tapscript-weak-finder"]
CMD ["serve", "--bind", "0.0.0.0:8787"]
