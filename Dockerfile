FROM docker.io/rust:1.65 as builder
WORKDIR /usr/src/myapp
COPY . .
RUN cargo install --path .

FROM docker.io/debian:bullseye-slim
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/ddns /usr/local/bin/ddns
ENV ACCESS_KEY_ID="" ACCESS_KEY_SECRET="" RR="" RECORD_ID=""
CMD ["ddns"]
