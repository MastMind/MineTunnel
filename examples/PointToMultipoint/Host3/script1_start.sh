#!/bin/sh

ip link set dev tun0 up
ip addr add 10.10.10.3/24 dev tun0
exit 0
