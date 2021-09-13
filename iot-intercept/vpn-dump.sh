ip=`curl -s https://ipinfo.io/ip`
iface="wlan0"   

mkdir -p $res_folder"/pcaps"
sudo tcpdump -Z varvello -i $iface -G 3600 -w "${ip}/pcaps/dump-"%m-%d-%Y-%H-%M".pcap" &
