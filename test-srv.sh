#!/bin/bash

SERVER_ITFC=enp1s0

SERVER_IP4=45.76.11.87

    iptables -t raw -A PREROUTING -j DROP   -s ${SERVER_IP4}
    iptables -t raw -A PREROUTING -j DROP   -i ${SERVER_ITFC} -s 172.16.0.0/16
    iptables -t raw -A PREROUTING -j ACCEPT -i ${SERVER_ITFC} -d ${SERVER_IP4}
    iptables -t raw -A PREROUTING -j ACCEPT -i ${SERVER_ITFC} -d ${SERVER_IP4}
    iptables -t raw -A PREROUTING -j ACCEPT -i ${SERVER_ITFC} -d ${SERVER_IP4}
    iptables -t raw -A PREROUTING -j DROP   -i ${SERVER_ITFC}
    iptables -t raw -A PREROUTING -j DROP   -d ${SERVER_IP4}
    iptables -t raw -A PREROUTING -j DROP   -d ${SERVER_IP4}
    iptables -t raw -A PREROUTING -j DROP   -d ${SERVER_IP4}
for ID in $(seq 15) ; do
    iptables -t raw -A PREROUTING -j DROP   -i xgw-${NID} ! -s 172.16.${NID}.0/24
    iptables -t raw -A PREROUTING -j ACCEPT -i xgw-${NID}   -d 172.16.${NID}.0
done
    iptables -t raw -A PREROUTING -j DROP -s 172.16.0.0/16
    iptables -t raw -A PREROUTING -j DROP -d 172.16.0.0/16


iptables -t nat -A POSTROUTING -s 172.16.0.0/16 -o ${SERVER_ITFC} -j MASQUERADE

for NID in $(seq 15) ; do
    echo 1 > /proc/sys/net/ipv4/conf/xgw-${NID}/forwarding
done

for NID in $(seq 15) ; do
    ip link set dev xgw-${NID}  up
    ip -4 addr add dev xgw-${NID} 172.16.${NID}.0/24 noprefixroute
    ip -4 route add metric 1 dev xgw-${NID} src 172.16.${NID}.0 172.16.${NID}.0/24
done

echo 1 > /proc/sys/net/ipv4/ip_forward

