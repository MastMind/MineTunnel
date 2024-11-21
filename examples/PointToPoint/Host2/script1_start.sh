#!/bin/sh

ip link set dev tun0 up
ip addr add 10.10.10.2/24 dev tun0
exit 0
