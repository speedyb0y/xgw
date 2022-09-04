#!/bin/bash

NODE_ID=1

XTUN_PREFIX=10.11.12

for ID in $(seq 15) ; do
    ip link set dev xgw-${ID}  up
    ip -4 addr add dev xgw-${ID} ${XTUN_PREFIX}.0
    ip -4 route add metric 1 dev xgw-${ID} src ${XTUN_PREFIX}.0 ${XTUN_PREFIX}.${ID}
done
