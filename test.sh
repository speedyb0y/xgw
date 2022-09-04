#!/bin/bash

ip link set dev enp5s0 up
ip link set dev enp6s0 up

ip -4 rule add table 5 to 10.11.12.0/24
ip -4 rule add table 5 from 10.11.12.0/24
ip -4 rule add table 5 oif xgw

ip link set dev xgw  up

ip -4 addr add 10.11.12.13/24 dev xgw

ip -4 route add table 5 dev xgw src 10.11.12.13 default
