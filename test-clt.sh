#!/bin/bash

SERVER_IP4=45.76.11.87

NODE_ID=1

ip link set dev enp5s0 up
ip link set dev enp6s0 up
ip link set dev xgw up

# NOTE: SE VAMOS FAZER FORWARDING, ENTAO
# ip -4 rule add table 4 to 172.16.${NODE_ID}.0/24
# ip -4 route add table 4 dev LAN_INTERFACE src 172.16.${NODE_ID}.20 172.16.${NODE_ID}.0/24

ip -4 rule add priority 4 table main  to ${SERVER_IP4}
ip -4 rule add priority 4 table isp-0 to ${SERVER_IP4}
ip -4 rule add priority 4 table isp-1 to ${SERVER_IP4}
ip -4 rule add priority 4 table isp-2 to ${SERVER_IP4}

ip -4 rule add priority 5 table 5 to 172.16.0.0/16
ip -4 rule add priority 5 table 5 from 172.16.0.0/16
ip -4 rule add priority 5 table 5 oif xgw

ip -4 addr add dev xgw 172.16.${NODE_ID}.20/24 noprefixroute
ip -4 route add table 5 dev xgw src 172.16.${NODE_ID}.20 default
