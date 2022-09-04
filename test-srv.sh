#!/bin/bash

for ID in $(seq 15) ; do
    iptables -t raw -A PREROUTING -j ACCEPT -s 172.16.${ID}.0/24   -d 172.16.${ID}.0/24 -i xgw-${ID}
    iptables -t raw -A PREROUTING -j ACCEPT -s 172.16.${ID}.0/24 ! -d 172.16.0.0/16     -i xgw-${ID}
done
    iptables -t raw -A PREROUTING -j DROP   -s 172.16.0.0/16
    iptables -t raw -A PREROUTING -j DROP   -d 172.16.0.0/16

iptables -t nat -A POSTROUTING -s 172.16.0.0/16 -o enp1s0 -j MASQUERADE

for ID in $(seq 15) ; do
    echo 1 > /proc/sys/net/ipv4/conf/xgw-${ID}/forwarding
done

for ID in $(seq 15) ; do
    ip link set dev xgw-${ID}  up
    ip -4 addr add dev xgw-${ID} 172.16.${ID}.0/24 noprefixroute
    ip -4 route add metric 1 dev xgw-${ID} src 172.16.${ID}.0 172.16.${ID}.0/24
done

echo 1 > /proc/sys/net/ipv4/ip_forward

