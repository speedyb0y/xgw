#!/bin/bash

SERVER_IP4=45.76.11.87

NID=1

TABLE_XGW_LAN=4
TABLE_XGW_SRV=5

ip link set dev enp5s0 up
ip link set dev enp6s0 up
ip link set dev xgw up

# XGW SERVER (REAL)
ip -4 rule add priority 2 table main  to ${SERVER_IP4}
ip -4 rule add priority 2 table isp-0 to ${SERVER_IP4}
ip -4 rule add priority 2 table isp-1 to ${SERVER_IP4}
ip -4 rule add priority 2 table isp-2 to ${SERVER_IP4}

# XGW SERVER -> XGW LAN
ip -4 rule add priority 3 table ${TABLE_XGW_LAN} from 172.16.${NID}.0
ip -4 rule add priority 3 table ${TABLE_XGW_LAN}  to  172.16.${NID}.0/24
ip -4 rule add priority 5 table ${TABLE_XGW_LAN} iif xgw

# XGW LAN -> XGW SERVER
ip -4 rule add priority 5 table ${TABLE_XGW_SRV}  to  172.16.${NID}.0
ip -4 rule add priority 5 table ${TABLE_XGW_SRV} from 172.16.${NID}.0/24
ip -4 rule add priority 5 table ${TABLE_XGW_SRV} oif xgw

#
ip -4 addr add dev xgw 172.16.${NID}.20/24 noprefixroute
ip -4 route add table ${TABLE_XGW_SRV} dev xgw src 172.16.${NID}.20 default
ip -4 route add table ${TABLE_XGW_LAN} dev LAN_INTERFACE src 172.16.${NID}.20 172.16.${NODE_I>
