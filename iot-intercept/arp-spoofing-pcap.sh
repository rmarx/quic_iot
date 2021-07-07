#!/bin/bash
## NOTE:   script to intercept IoT traffic via ARP spoofing
## Author: Matteo Varvello <matteo.varvello@nokia.com>
## Requirements: sudo apt-get install dsniff

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT
function ctrl_c() {
	echo "[$0][`date`] Trapped ctrl-c" 
	stop_all
}

# load device info: <name, ip, mac>
read_device_info(){
	first="true"
	while read line 
	do 
		name=`echo "$line" | cut -f 1 -d " "`
		ip=`echo "$line" | cut -f 2 -d " "`
		mac=`echo "$line" | cut -f 3 -d " "`
		device_list[$name]=$ip
		if [ $first == "true" ] 
		then 
			filter="host $ip"
			first="false"
		else
			filter=$filter" or host "$ip
		fi 
	done < $1
}

# stop all 
stop_all(){
	echo "[$0][`date`] Requested to stop all" 
	for pid in `ps aux | grep "arpspoof" | grep -v "grep" | awk '{print $2}'`
	do 
		echo "[$0][`date`] Stopping PID $pid"
		sudo kill -SIGINT $pid
	done
	echo "[$0][`date`] Stopping tcpdump" 
	sudo killall tcpdump 
}

# parameters 
declare -A device_list   # dictionaire of device info
filter=""                # tcpdump filter to be used 
iface="enp5s0"           # interface to use for pcap collection 
router="192.168.1.1"     # home router IP address 
id=`date +%s`            # unique id for this run 

# stop all currently running if requested 
stop_all
if [ $# -eq 1 ] 
then 
	exit 0 
fi 

# logging 
echo "[$0][`date`] Test identifier: $id"

# read supported device information 
#read_device_info "device-info-short.txt"
read_device_info "device-info.txt"

# start ARP spoofing per device 
res_folder=`pwd`"/results/$id"
mkdir -p $res_folder"/logs"
for device in "${!device_list[@]}"
do 
	ip=${device_list[$device]}
	echo "[$0][`date`] Starting ARP spoofing for $device ($ip)"
	(sudo arpspoof -i $iface -t $ip $router > "${res_folder}/logs/arp-${device}-1" 2>&1 &)
	(sudo arpspoof -i $iface -t $router $ip > "${res_folder}/logs/arp-${device}-2" 2>&1 &)
done 

# start pcap collection 	
mkdir -p $res_folder"/pcaps/"	
pcap_file="${res_folder}/pcaps/test.pcap"
if [ -f $pcap_file ] 
then 
	sudo rm $pcap_file
fi 
filter=$filter" and not arp" 
echo "[$0][`date`] Starting PCAP collection ($pcap_file => $filter)"
#echo "sudo tcpdump -Z varvello -i $iface -w $pcap_file -W 48 -G 1800 -C 10 -K -n $filter"
#sudo tcpdump -Z varvello -i $iface -w $pcap_file -W 48 -G 1800 -C 10 -K -n $filter #> "${res_folder}/logs/pcap-log" 2>&1 &
sudo tcpdump -Z varvello -i $iface -G 3600 -w "${res_folder}/pcaps/dump-"%m-%d-%Y-%H-%M".pcap" $filter & 
#echo "sudo tcpdump -i $iface -w $pcap_file $filter"
#sudo tcpdump -i $iface -w $pcap_file $filter
#sudo tcpdump -i $iface -w $pcap_file -W 48 -G 1800 -C 100 -K -n host $ip and not arp &
