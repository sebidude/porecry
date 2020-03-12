FROM golang:1.14-alpine as builder

RUN apk add --no-cache --update git make
RUN mkdir /build
WORKDIR /build
RUN git clone https://github.com/sebidude/porecry.git
WORKDIR /build/porecry
RUN make unittests build-linux test

FROM scratch

COPY --from=builder /build/porecry/build/linux/porecry /usr/bin/porecry
ENTRYPOINT ["/usr/bin/porecry"]
