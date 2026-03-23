SET interface_name="tun0"
SET static_ip=10.10.10.1
SET subnet_mask=255.255.255.0

netsh interface ipv4 set address name=%interface_name% source=static address=%static_ip% mask=%subnet_mask%
