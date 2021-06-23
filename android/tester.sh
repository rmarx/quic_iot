#!/bin/bash
## Note:   Script to automate a bunch of IoT apps
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

# find package and verify IoT app is installed
find_package(){
    if [ $app == "wyze" ]
    then 
        package="com.hualai"
    elif [ $app == "smartlife" ]
    then 
        package="com.tuya.smartlife" 
    elif [ $app == "alexa" ] 
	then 
		package="com.amazon.dee.app"
	elif [ $app == "google" ]
	then 
		package="com.google.android.apps.chromecast.app"
	elif [ $app == "smartthings" ] 
	then 
		package="com.samsung.android.oneconnect"
	else
		echo "App $app not supported" 
		exit -1  
	fi 
    
	# make sure app is installed? 
    adb shell 'pm list packages -f' | grep $package 
    if [ $? -ne 0 ] 
    then 
        myprint "Something is wrong. Package $package was not found. Please install it" 
        exit -1
    fi 
}

# script usage
usage(){
    echo "==========================================================================================="
    echo "USAGE: $0 -a/--app, -i/--id, --pcap, --vpn, -d/--dur"
    echo "==========================================================================================="
    echo "-a/--app        app to be tested [wyze, smartlife, alexa, google, smartthings]"
    echo "-i/--id         test identifier to be used" 
    echo "--vpn           flag to control if to use a VPN" 
    echo "-d, --dur       duration, time spent within a command"
    echo "==========================================================================================="
    exit -1
}

# general parameters
package=""                               # package of videoconferencing app to be tested
duration=10                              # default test duration before leaving the call
test_id=`date +%s`                       # unique test identifier 
pcap_collect="false"                     # flag to control pcap collection ar router
iface="wlan0"                            # current default interface where to collect data
use_vpn="false"                          # flag to control if to use a VPN or not
device_id="R38M20L7BMZ"

# read input parameters
while [ "$#" -gt 0 ]
do
    case "$1" in
        -a | --app)
            shift; app="$1"; shift;
            ;;
        -h | --help)
            usage
            ;;
		-d | --dur)
			shift; duration="$1"; shift;
			;;
        -i | --id)
            shift; test_id="$1"; shift;
            ;;
        --pcap)
            shift; pcap_collect="true";
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

# check that app is supported and find its package 
find_package

# folder organization
res_folder="./results/${test_id}"
mkdir -p $res_folder 

# close all pending apps
close_all

# check for right wifi connection
SSID=`adb -s $device_id shell dumpsys netstats | grep -E 'iface=wlan.*networkId' | head -n 1  | awk '{split($4, A,"="); split(A[2], B, ","); gsub("\"", "",  B[1]); print B[1]}'`
myprint "WiFI: $SSID"

# cleanup logcat
for pid in `ps aux | grep "adb" | grep "logcat"  | awk '{print $2}'`; do  kill -9 $pid; done
adb -s $device_id logcat -c 

# start app 
t_launch=`date +%s` 
echo "[$0][$app][`date +%s`] LAUNCHED"
adb -s $device_id shell monkey -p $package 1
touch ".launched" # singal that app was launched 

# allow time for app to launch
sleep 5 

# execute command 
if [ $app == "wyze" ] 
then 
	echo "[$0][$app][`date +%s`] Getting access to video feed" 
	tap_screen 540 719
	sleep $duration 
	echo "[$0][$app][`date +%s`] Getting out of video feed" 
	tap_screen 60 167
elif [ $app == "smartlife" ]  
then
	echo "[$0][$app][`date +%s`] Turning smart plug either ON or OFF"
	tap_screen 937 651
	sleep $duration 
elif [ $app == "alexa" ] 
then 	
	echo "[$0][$app][`date +%s`] Turning music on" 
	tap_screen 543 2080 1
	tap_screen 209 491 1
	tap_screen 540 2016 1
	sleep $duration 
	echo "[$0][$app][`date +%s`] Turning music off" 
	tap_screen 880 1960 1
elif [ $app == "google" ] 
then 	
	echo "[$0][$app][`date +%s`] Turning music on" 
	tap_screen 280 1414
	sleep $duration 
	echo "[$0][$app][`date +%s`] Turning music on" 
	tap_screen 280 1414
elif [ $app == "smartthings" ] 
then
	echo "[$0][$app][`date +%s`] Turning smart plug either ON or OFF"
	tap_screen 454 1375
	sleep $duration 
fi 

# close all pending apps
close_all
echo "[$0][$app][`date +%s`] CLOSED"
