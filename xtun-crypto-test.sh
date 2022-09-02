#!/bin/bash

ALGO=${1^^}

if gcc -fwhole-program -Wall -Wextra -O2 -march=native xtun-crypto-test.c \
    -DTEST_CRYPTO_ALGO=XTUN_CRYPTO_ALGO_${ALGO} \
    -DTEST_CHUNK_SIZE_MIN=128 \
    -DTEST_CHUNK_SIZE_MAX=1500 \
    -DTEST_ENCODE=1 \
    -DTEST_DECODE=1 \
    -DTEST_VERIFY_DATA=1 \
    -DTEST_VERIFY_HASH=1 \
    -DTEST_ORIGINAL=1 \
    -DTEST_PRINT=1 \
    -DTEST_LOOPS=4 ; then
        ./a.out < /dev/zero | pv > /dev/null
fi