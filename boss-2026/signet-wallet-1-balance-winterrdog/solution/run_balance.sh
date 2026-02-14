#!/usr/bin/env bash

SECP_LIB="./solution/cpp/secp256k1/lib"
SECP_INC="./solution/cpp/secp256k1/include"

if [ ! -f "$SECP_LIB/libsecp256k1.a" ]; then
    echo "ERROR: libsecp256k1.a not found at $SECP_LIB/libsecp256k1.a"
    exit 1
fi

g++ -std=c++17 -O2 -o ./solution/cpp/bb \
    ./solution/cpp/base58/base58.cc \
    ./solution/cpp/common/common.cc \
    ./solution/cpp/common/bitcoin_amt.cc \
    ./solution/cpp/balance/balance.cc \
    ./solution/cpp/main.cc \
    -I"$SECP_INC" \
    -L"$SECP_LIB" \
    -lsecp256k1 \
    -lcrypto \
    -lssl 2>&1 && ./solution/cpp/bb balance
