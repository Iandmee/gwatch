FROM alpine:latest
RUN apk add --no-cache --update cmake gcc g++ clang gdb make ninja build-essential libtool autoconf unzip wget boost boost-dev\
    rm -rf / tmp/* /var/cache/apk/*

COPY . /testBinary
WORKDIR testBinary
RUN mkdir build && cd build && cmake .. && make
#CMD ["./build/TestAppVariableAccess"]