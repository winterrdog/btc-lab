#!/usr/bin/env bash

# BASE_DIR="./solution/cpp" # used in GHA runners in production
BASE_DIR="./cpp" # for local testing

OUTPUT="bcs"
CXXFLAGS="-std=c++20 -Wall -Wpedantic -Wextra -O2"
SOURCES="$BASE_DIR/main.cc $BASE_DIR/coin-selection.cc $BASE_DIR/common.cc"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFINES="-DPROJECT_DIR=\"${PROJECT_DIR}\""

INCLUDES="-I$BASE_DIR/json.hpp"
# INCLUDES=""

# compile
g++ ${CXXFLAGS} ${DEFINES} ${INCLUDES} ${SOURCES} -o ${OUTPUT}
if [ $? -eq 0 ]; then
    ./$OUTPUT
else
    echo "- build failed!"
    exit 1
fi
