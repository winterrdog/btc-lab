#!/usr/bin/env bash

BASE_DIR="./solution/cpp" # used in GHA runners in production
# BASE_DIR="./cpp" # for local testing

SECP_LIB="$BASE_DIR/secp256k1/lib"
SECP_INC="$BASE_DIR/secp256k1/include"

if [ ! -f "$SECP_LIB/libsecp256k1.a" ]; then
    echo "error: libsecp256k1.a not found at $SECP_LIB/libsecp256k1.a"
    exit 1
fi

g++ -std=c++20 -Wextra -Wpedantic -Ofast -o "$BASE_DIR/ss" \
    "$BASE_DIR/common/bitcoin_amt.cc" \
    "$BASE_DIR/balance/balance.cc" \
    "$BASE_DIR/common/common.cc" \
    "$BASE_DIR/base58/base58.cc" \
    "$BASE_DIR/spend/spend.cc" \
    "$BASE_DIR/main.cc" \
    -I"$SECP_INC" \
    -L"$SECP_LIB" \
    -lsecp256k1 \
    -lcrypto \
    -lssl 2>&1 && "$BASE_DIR/ss" spend
