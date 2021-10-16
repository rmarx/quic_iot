sudo iptables -I FORWARD -d 192.168.5.6 -j NFQUEUE --queue-num 1
sudo iptables -I FORWARD -s 192.168.5.6 -j NFQUEUE --queue-num 1

sudo iptables -I FORWARD -d 192.168.5.14 -j NFQUEUE --queue-num 1
sudo iptables -I FORWARD -s 192.168.5.14 -j NFQUEUE --queue-num 1

sudo iptables -I FORWARD -d 192.168.5.15 -j NFQUEUE --queue-num 1
sudo iptables -I FORWARD -s 192.168.5.15 -j NFQUEUE --queue-num 1

sudo iptables -I FORWARD -d 192.168.5.19 -j NFQUEUE --queue-num 1
sudo iptables -I FORWARD -s 192.168.5.19 -j NFQUEUE --queue-num 1


# sudo iptables -D FORWARD -d 192.168.5.6 -j NFQUEUE --queue-num 1
# sudo iptables -D FORWARD -s 192.168.5.6 -j NFQUEUE --queue-num 1

# sudo iptables -D FORWARD -d 192.168.5.14 -j NFQUEUE --queue-num 1
# sudo iptables -D FORWARD -s 192.168.5.14 -j NFQUEUE --queue-num 1

# sudo iptables -D FORWARD -d 192.168.5.15 -j NFQUEUE --queue-num 1
# sudo iptables -D FORWARD -s 192.168.5.15 -j NFQUEUE --queue-num 1

# sudo iptables -D FORWARD -d 192.168.5.19 -j NFQUEUE --queue-num 1
# sudo iptables -D FORWARD -s 192.168.5.19 -j NFQUEUE --queue-num 1