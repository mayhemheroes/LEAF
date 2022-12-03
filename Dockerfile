FROM debian:bookworm as builder

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install build-essential clang -y

ADD . /leaf
WORKDIR /leaf/fuzz

RUN make

FROM debian:bookworm
COPY --from=builder /leaf/fuzz/leaf-fuzzer /