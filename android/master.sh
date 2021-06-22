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
    echo "USAGE: $0 -i/--id, --vpn, -d/--dur"
    echo "==========================================================================================="
    echo "-i/--id         test identifier to be used" 
    echo "--vpn           flag to control if to use a VPN" 
    echo "-d, --dur       duration, time spent within a command"
    echo "==========================================================================================="
    exit -1
}

# general parameters
duration=10                              # default test duration before leaving the call
test_id=`date +%s`                       # unique test identifier 

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
        -*)
            echo "ERROR: Unknown option $1"
            usage
            ;;
    esac
done


# external loop 
echo "[$0][`date +%s`] TestID: $test_id" 
num_run=1
target_runs=1
#APP_LIST=( "wyze" "smartlife" "alexa" "google" "smartthings" )
APP_LIST=( "alexa" "google" )
while [ $num_run -le $target_runs ] 
do 
	# iterate on app to be tested 
	for app in "${APP_LIST[@]}"
	do
		id=$test_id"/"$app"/"$num_run
		res_folder="./results/${id}"
		mkdir -p $res_folder 
		clean_file ".launched" 
		echo "[$0][`date +%s`] ./tester.sh -a $app -i $id -d $duration"
		(./tester.sh -a $app -i $id -d $duration > $res_folder"/log.txt" 2>&1 &)
		ready="false" 
		while [ $ready == "false" ] 
		do 
			if [ -f ".launched" ] 
			then 
				ready="true" 
			else 
				sleep 0.1
			fi 
		done
		# TODO: start reporting to IoT proxy via QUIC 
		# wait for experiment to end 
		echo "[$0][`date +%s`] $app was launched. Waiting for it to complete..."
		sleep $duration 
		ps aux | grep tester | grep -v "grep" > /dev/null
		ans=$?
		while [ $ans -eq 0 ] 
		do 
			sleep 2
			ps aux | grep tester | grep -v "grep" > /dev/null
			ans=$?
		done
		echo "[$0][`date +%s`] $app has completed" 
	done
	let "num_run++" 
done

