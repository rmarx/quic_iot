#!/bin/bash
## Note:   Script for driving experiments
## Author: Matteo Varvello
## Date:   06/22/2021

#helper to  load utilities files
load_file(){
    if [ -f $1 ]
    then
        source $1
    else
        echo "Utility file $1 is missing"
        exit -1
    fi
}

# import utilities files needed
curr_dir=`pwd`
base_dir=$curr_dir
adb_file=$base_dir"/adb-utils.sh"
load_file $adb_file

# cleanup - make sure nothign is running 
cleanup(){
	command="sudo killall tcpdump"
	ssh -o StrictHostKeyChecking=no -p 12345 $iot_proxy "$command"
	echo "[$0][`date +%s`] Stopped PCAP collection"
	command="killall python3"
	ssh -o StrictHostKeyChecking=no -p 12345 $iot_proxy "$command"
	echo "[$0][`date +%s`] Stopped QUIC+ML server" 
}

keep_ssh(){
	myprint "Adding rules to keep SSH alive despite the VPN"
	sudo ip rule add from $(ip route get 1 | grep -Po '(?<=src )(\S+)') table 128
    sudo ip route add table 128 to $(ip route get 1 | grep -Po '(?<=src )(\S+)')/32 dev $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)')
    sudo ip route add table 128 default via $(ip -4 route ls | grep default | grep -Po '(?<=via )(\S+)')
}

#function to wait for VPN to be ready
wait_for_vpn(){
	MAX_CONN_TIME=30
	t_s=`date +%s`
	echo "Waiting up to $MAX_CONN_TIME secs for <<Initialization Sequence Complete>>"
	while [ $vpn_ready == "false" ]
	do
		if [ ! -f $log_vpn ] 
		then 
			echo "VPN-log $log_vpn is missing"
			sleep 3 
		fi 
		cat $log_vpn | grep "Initialization Sequence Completed"
		ans=$?
		if [ $ans -eq 0 ]
		then
			my_ip=`curl -s https://ipinfo.io/ip`
			vpn_ready="true"
			echo "VPN setup. New IP: $my_ip"
		else
			sleep 1
			t_c=`date +%s`
			let "t_p = t_c - t_s"
			if [ $t_p -gt $MAX_CONN_TIME -a $vpn_ready == "false" ]
			then
				echo "Timeout detected for $curr_vpn - Aborting"
				break
			fi
		fi
	done
}

# function to make sure VPN is off
vpn_off(){
	echo "turning VPN off"
	for pid in `ps aux | grep "openvpn" | grep -v "grep" | awk '{print $2'}`
	do 
		sudo  kill -9 $pid 
	done  
}

# script usage
usage(){
    echo "==========================================================================================="
    echo "USAGE: $0 -i/--id, --vpn, -d/--dur, --pcap, --lan, --clean"
    echo "==========================================================================================="
    echo "-i/--id         test identifier to be used" 
    echo "--vpn           flag to control if to use a VPN" 
    echo "--pcap          flag to control pcap collection at the pi"
    echo "--quic          use quic" 
    echo "--rand          use random duration and sleeps" 
    echo "--lan           use LAN comm to IoT proxy" 
    echo "--clean         only stop processes at IoT proxy and leave" 
    echo "-d, --dur       duration, time spent within a command"
    echo "==========================================================================================="
    exit -1
}

# general parameters
duration=20                     # default test duration before leaving the call
test_id=`date +%s`              # unique test identifier 
pcap="false"                    # default do not collect traffic
iot_proxy="iot.batterylab.dev"  # address of iot proxy 
iot_port="7352"                 # port to be used 
use_quic="false"                # by default no quic is used 
use_random="false"              # by default no random durations or sleeps
clean_only="false" 
use_lan="false"

# read input parameters
while [ "$#" -gt 0 ]
do
    case "$1" in
        -h | --help)
            usage
            ;;
		-d | --dur)
			shift; duration="$1"; shift;
			;;
        --vpn)
            shift; use_vpn="true"; location="$1"; shift; 
			;;
        --pcap)
            shift; pcap="true";  
			;;
        --quic)
            shift; use_quic="true";  
			;;
        --rand)
            shift; use_random="true";  
			;;
        --clean)
            shift; clean_only="true";  
			;;
        --lan)
            shift;
			iot_proxy="192.168.1.246" 
			use_lan="true"
			echo "Switching to internal comm with IoT proxy"
			;;
        -*)
            echo "ERROR: Unknown option $1"
            usage
            ;;
    esac
done

# logging 
echo "Using IoT proxy: $iot_proxy:$iot_port"

# cleanup - make sure nothing is running 
cleanup
if [ $clean_only == "true" ] 
then 
	echo "Cleanup done" 
	exit -1 
fi 
 
# start quic server-side component 
if [ $use_quic == "true" ] 
then 
	echo "[$0][`echo $(($(date +%s%N)/1000000))`] Starting IoT proxy (QUIC+ML)"
	if [ $use_lan == "true" ] 
	then 
		ip_iot_proxy=$iot_proxy
	else 
		ip_iot_proxy=`dig $iot_proxy | grep "ANSWER SECTION" -A 1 | grep -v ANSWER | awk '{print $NF}'`
	fi 
	command="cd /home/pi/quic/aioquic && python3 -u examples/fiat_server.py --certificate tests/ssl_cert.pem --private-key tests/ssl_key.pem --port $iot_port --fiat-log logs/fiat_server_$test_id.log --preprocess 0 > logs/outlog_$test_id 2>&1"
	ssh -o StrictHostKeyChecking=no -p 12345 $iot_proxy "$command" & 
fi 

# collect pcap if requested
if [ $pcap == "true" ] 
then 
	echo "[$0][`echo $(($(date +%s%N)/1000000))`] Started PCAP collection"
	command="cd /home/pi/quic_iot/android/pcaps &&	sudo tcpdump -i wlan0 -w $test_id.pcap > /dev/null 2>&1"
	ssh  -o StrictHostKeyChecking=no -p 12345 $iot_proxy "$command" & 
fi 

# external loop 
echo "[$0][`echo $(($(date +%s%N)/1000000))`] TestID: $test_id" 
num_run=1
target_runs=5
#APP_LIST=( "wyze" "smartlife" "alexa" "google" "smartthings" )
APP_LIST=( "wyze" "smartlife" "alexa" "google" )
#APP_LIST=( "alexa" )
while [ $num_run -le $target_runs ] 
do 
	# iterate on app to be tested 
	for app in "${APP_LIST[@]}"
	do
		id=$test_id"/"$app"/"$num_run
		res_folder=`pwd`"/results/${id}"
		mkdir -p $res_folder 

		# start reporting to IoT proxy via QUIC (use sync in there) 
		launch_file=`pwd`"/.launched"
		clean_file $launch_file
		if [ $use_quic == "true" ] 
		then 
			cd 	/home/pi/quic_iot/aioquic
			echo "[$0][`echo $(($(date +%s%N)/1000000))`] Launching fiat_client.py" 
			(python3 -u examples/fiat_client.py --ca-certs tests/pycacert.pem https://$ip_iot_proxy:$iot_port/ --fiat-log $res_folder/fiat_client_$test_id.log --preprocess 0  --ready $launch_file --zero-rtt > $res_folder/outlog_$test_id 2>&1 &) 
			cd - > /dev/null 2>&1 
		fi 
	
		# launch the app 
		if [ $use_random == "true" ] 
		then 
			random_duration=`echo $((5 + $RANDOM % 30))`
			echo "[$0][`echo $(($(date +%s%N)/1000000))`] Random duration: $random_duration" 
			duration=$random_duration 
		fi 
		echo "[$0][`echo $(($(date +%s%N)/1000000))`] ./tester.sh -a $app -i $id -d $duration"
		(./tester.sh -a $app -i $id -d $duration > $res_folder"/log.txt" 2>&1 &)
		
		# wait for experiment to end 
		echo "[$0][`echo $(($(date +%s%N)/1000000))`] $app was launched. Waiting for it to complete..."
		sleep $duration 
		ps aux | grep tester | grep -v "grep" > /dev/null
		ans=$?
		while [ $ans -eq 0 ] 
		do 
			sleep 2
			ps aux | grep tester | grep -v "grep" > /dev/null
			ans=$?
		done
		echo "[$0][`echo $(($(date +%s%N)/1000000))`] $app has completed" 

		# stop the quic client 
		if [ $use_quic == "true" ] 
		then 
			killall python3
			echo "[$0][`echo $(($(date +%s%N)/1000000))`] Stopped QUIC client" 
		fi 

		# sleep in between apps
		if [ $use_random == "true" ] 
		then 
			random_sleep=`echo $((60 + $RANDOM % 600))`
			echo "[$0][`echo $(($(date +%s%N)/1000000))`] Random sleep: $random_sleep sec" 
			sleep $random_sleep 
		else 
			echo "[$0][`echo $(($(date +%s%N)/1000000))`] Sleep between devices: 30 sec" 
			sleep 30 
		fi  
	done
	let "num_run++" 
done

# final cleanup 
cleanup 
