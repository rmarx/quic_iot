sudo killall tcpdump

ip=`curl -s https://ipinfo.io/ip`
iface="wlan0"   

mkdir -p "${ip}"
sudo tcpdump -i $iface -G 3600 -w "${ip}/dump-"%m-%d-%Y-%H-%M".pcap" &
