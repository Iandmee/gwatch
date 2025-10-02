FROM --platform=linux/arm64 alpine:latest

RUN apk add --no-cache --update cmake gcc g++ clang gdb make ninja build-essential libtool autoconf unzip wget boost boost-dev\
    rm -rf / tmp/* /var/cache/apk/*

COPY . /gwatch
WORKDIR /gwatch

#Build target binary
RUN cd testBinary && \
    mkdir -p build && cd build && \
    cmake .. && \
    make

RUN mkdir -p build && cd build && \
    cmake .. && \
    make

# Copy target binary
RUN cp testBinary/build/TestAppVariableAccess build

WORKDIR /gwatch/build
