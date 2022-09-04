#!/bin/bash

SERVER_IP4=45.76.11.87

NID=1

ip link set dev enp5s0 up
ip link set dev enp6s0 up
ip link set dev xgw up

# XGW SERVER (REAL)
ip -4 rule add priority 2 table main  to ${SERVER_IP4}
ip -4 rule add priority 2 table isp-0 to ${SERVER_IP4}
ip -4 rule add priority 2 table isp-1 to ${SERVER_IP4}
ip -4 rule add priority 2 table isp-2 to ${SERVER_IP4}

# XGW SERVER -> XGW LAN
ip -4 rule add prioritu 3 table 3 from 172.16.${NID}.0
ip -4 rule add prioritu 3 table 3  to  172.16.${NID}.0/20
ip -4 rule add priority 5 table 5 iif xgw

# XGW LAN -> XGW SERVER
ip -4 rule add priority 5 table 5  to  172.16.${NID}.0
ip -4 rule add priority 5 table 5 from 172.16.${NID}.0/20
ip -4 rule add priority 5 table 5 oif xgw

# NOTE: SE VAMOS FAZER FORWARDING, ENTAO
# ip -4 rule add table 4 to 172.16.${NID}.0/24
# ip -4 route add table 4 dev LAN_INTERFACE src 172.16.${NID}.20 172.16.${NODE_I>

ip -4 addr add dev xgw 172.16.${NID}.20/24 noprefixroute
ip -4 route add table 5 dev xgw src 172.16.${NID}.20 default
