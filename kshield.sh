#!/bin/bash

# Flush existing rules
/sbin/iptables -F
/sbin/iptables -X
/sbin/iptables -t nat -F
/sbin/iptables -t nat -X
/sbin/iptables -t mangle -F
/sbin/iptables -t mangle -X
/sbin/iptables -t raw -F
/sbin/iptables -t raw -X

# Drop bogon source IPs in mangle PREROUTING
/sbin/iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP

# Block unusual TCP flags in mangle PREROUTING
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# Enable SYNPROXY at raw table (must be first)
/sbin/iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack
/sbin/iptables -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460

# SYN flood protection (early in chain)
/sbin/iptables -A INPUT -p tcp --syn -m hashlimit \
    --hashlimit-name synflood \
    --hashlimit-above 30/sec \
    --hashlimit-burst 10 \
    --hashlimit-mode srcip \
    --hashlimit-htable-size 32768 \
    --hashlimit-htable-expire 30000 \
    -j DROP

# Additional SYN protection layers
/sbin/iptables -A INPUT -p tcp --syn -m recent --name synflood --set
/sbin/iptables -A INPUT -p tcp --syn -m recent --name synflood --rcheck --seconds 1 --hitcount 20 -j DROP

# Strict connection limits for SYN
/sbin/iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 15 --connlimit-mask 32 -j DROP

# TCP SYN-specific settings
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 1 > /proc/sys/net/ipv4/tcp_synack_retries
echo 5 > /proc/sys/net/ipv4/tcp_syn_retries
echo 1 > /proc/sys/net/ipv4/tcp_timestamps
echo 30 > /proc/sys/net/ipv4/tcp_fin_timeout
echo 1280 > /proc/sys/net/ipv4/tcp_max_syn_backlog

# Add comprehensive logging at the start
/sbin/iptables -N LOGGING
/sbin/iptables -A INPUT -j LOGGING
/sbin/iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Initial-Input: " --log-level 4
/sbin/iptables -A LOGGING -j RETURN

# Allow all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
/sbin/iptables -A INPUT -i lo -j ACCEPT
/sbin/iptables -A INPUT -s 127.0.0.0/8 -j DROP

# Allow SSH traffic
/sbin/iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# HTTP/HTTPS rules with proper connection handling
/sbin/iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
/sbin/iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
/sbin/iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 1000/minute --limit-burst 2000 -j ACCEPT
/sbin/iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 1000/minute --limit-burst 2000 -j ACCEPT

# Allow established and related connections
/sbin/iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow ICMP echo requests (ping) with rate limiting
/sbin/iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT
# Drop packets from IPs with excessive connections
/sbin/iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP

# Use SYNPROXY to protect against SYN flood attacks
/sbin/iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack
/sbin/iptables -A INPUT -p tcp -m tcp --syn -m conntrack --ctstate NEW -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
/sbin/iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Drop packets from blacklisted IPs
/sbin/iptables -A INPUT -s 1.2.3.4 -j DROP
/sbin/iptables -A INPUT -s 5.6.7.8 -j DROP

# Log and drop excessive traffic
/sbin/iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables: "
/sbin/iptables -A INPUT -j DROP

# Port scanning protection
/sbin/iptables -N port-scanning
/sbin/iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
/sbin/iptables -A port-scanning -j DROP

# Block DNS amplification attacks
/sbin/iptables -A INPUT -p udp --dport 53 -m string --algo bm --string "ANY" -j DROP
/sbin/iptables -A INPUT -p udp --dport 53 -m limit --limit 10/s --limit-burst 20 -j ACCEPT
/sbin/iptables -A INPUT -p udp --dport 53 -j DROP

# Block NTP amplification attacks
/sbin/iptables -A INPUT -p udp --dport 123 -m u32 --u32 "0x0>>0x16&0x3c@0x8&0xff=0x17" -j DROP
/sbin/iptables -A INPUT -p udp --dport 123 -m limit --limit 10/s --limit-burst 20 -j ACCEPT
/sbin/iptables -A INPUT -p udp --dport 123 -j DROP

# Block SSDP amplification attacks
/sbin/iptables -A INPUT -p udp --dport 1900 -m string --algo bm --string "M-SEARCH" -j DROP
/sbin/iptables -A INPUT -p udp --dport 1900 -m limit --limit 10/s --limit-burst 20 -j ACCEPT
/sbin/iptables -A INPUT -p udp --dport 1900 -j DROP

# Block LDAP amplification attacks
/sbin/iptables -A INPUT -p udp --dport 389 -m string --algo bm --string "(&(objectClass=*))" -j DROP
/sbin/iptables -A INPUT -p udp --dport 389 -m limit --limit 10/s --limit-burst 20 -j ACCEPT
/sbin/iptables -A INPUT -p udp --dport 389 -j DROP

# Block UDP flood attacks
/sbin/iptables -A INPUT -p udp -m limit --limit 10/s --limit-burst 20 -j ACCEPT
/sbin/iptables -A INPUT -p udp -j DROP

# Add a global rate limit for inbound UDP
/sbin/iptables -A INPUT -p udp -m limit --limit 200/s --limit-burst 500 -j ACCEPT

# Automatically blacklist UDP offenders who exceed thresholds repeatedly
/sbin/iptables -A INPUT -p udp -m recent --name badguys --rcheck --seconds 60 --hitcount 20 -j DROP
/sbin/iptables -A INPUT -p udp -m recent --name badguys --set -j ACCEPT

# Block TCP NULL attacks
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Rate limit TCP SYN-ACK packets to mitigate SYN-ACK flood attacks
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m limit --limit 10/s --limit-burst 20 -j ACCEPT
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -j DROP

# Block TCP FIN scan attacks
/sbin/iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP

# Block TCP XMAS scan attacks
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP

# Log packets before the catch-all DROP rule
/sbin/iptables -A INPUT -j LOG --log-prefix "iptables-dropped: " --log-level 4

# Catch-all DROP rule
/sbin/iptables -A INPUT -j DROP

# Enhanced SYN flood protection
/sbin/iptables -A INPUT -p tcp --syn -m hashlimit \
    --hashlimit-name synflood \
    --hashlimit-above 200/sec \
    --hashlimit-burst 3 \
    --hashlimit-mode srcip \
    --hashlimit-htable-size 32768 \
    --hashlimit-htable-max 32768 \
    --hashlimit-htable-expire 180000 \
    -j DROP

# TCP connection limits per IP
/sbin/iptables -A INPUT -p tcp -m connlimit --connlimit-above 30 --connlimit-mask 32 -j DROP
/sbin/iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 15 --connlimit-mask 32 -j DROP

# Enhanced HTTP/HTTPS protection
/sbin/iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m hashlimit \
    --hashlimit-name http \
    --hashlimit-above 50/sec \
    --hashlimit-burst 200 \
    --hashlimit-mode srcip \
    --hashlimit-htable-size 32768 \
    --hashlimit-htable-max 32768 \
    --hashlimit-htable-expire 180000 \
    -j ACCEPT

/sbin/iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m hashlimit \
    --hashlimit-name https \
    --hashlimit-above 50/sec \
    --hashlimit-burst 200 \
    --hashlimit-mode srcip \
    --hashlimit-htable-size 32768 \
    --hashlimit-htable-max 32768 \
    --hashlimit-htable-expire 180000 \
    -j ACCEPT

# Protection against ACK flood
/sbin/iptables -A INPUT -p tcp --tcp-flags ACK ACK -m hashlimit \
    --hashlimit-name ack-flood \
    --hashlimit-above 100/sec \
    --hashlimit-burst 150 \
    --hashlimit-mode srcip \
    --hashlimit-htable-size 32768 \
    --hashlimit-htable-expire 180000 \
    -j DROP

# Protection against RST flood
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -m hashlimit \
    --hashlimit-name rst-flood \
    --hashlimit-above 100/sec \
    --hashlimit-burst 150 \
    --hashlimit-mode srcip \
    --hashlimit-htable-size 32768 \
    --hashlimit-htable-expire 180000 \
    -j DROP

# Enhanced UDP flood protection
/sbin/iptables -A INPUT -p udp -m hashlimit \
    --hashlimit-name udp-flood \
    --hashlimit-above 100/sec \
    --hashlimit-burst 150 \
    --hashlimit-mode srcip \
    --hashlimit-htable-size 32768 \
    --hashlimit-htable-expire 180000 \
    -j DROP

# ICMP flood protection
/sbin/iptables -A INPUT -p icmp --icmp-type echo-request -m hashlimit \
    --hashlimit-name ping-flood \
    --hashlimit-above 5/sec \
    --hashlimit-burst 10 \
    --hashlimit-mode srcip \
    --hashlimit-htable-size 32768 \
    --hashlimit-htable-expire 180000 \
    -j ACCEPT

# Recent attacker blocking
/sbin/iptables -A INPUT -m recent --name badguys --update --seconds 60 --hitcount 20 -j DROP
/sbin/iptables -A INPUT -m recent --name badguys --set -j ACCEPT