#!/bin/bash

for ID in $(seq 15) ; do
    ip link set dev xgw-${ID}  up
    ip -4 addr add dev xgw-${ID} 172.16.${ID}.0
    ip -4 route add metric 1 dev xgw-${ID} src 172.16.${ID}.0 172.16.${ID}.0/16
done
