#!/bin/bash 
## Set up remote access to Android devices
## Author: Matteo Varvello 
## Date: 09/102020

# print script usage 
usage(){
    echo "===================================================================="
    echo "USAGE: $0 -s,--screen d,--device p,--port -h,--help, --id"
    echo "===================================================================="
    echo "-s,--screen     Virtual screen to be used (default :3)"
    echo "-d,--device     Real device to be used (default: emulator)"
    echo "-v,--video      Record screen (default: False)" 
    echo "-p,--port       noVNC port (default: 6081)" 
    echo "-h,--help       Shows an helper" 
    echo "--id            Session identifier"
    echo "===================================================================="
    exit -1 
}

# import file with common function
#common_file=$HOME"/batterylab/src/automation/common.sh"
#if [ -f $common_file ]
#then
#    source $common_file
#else
#    echo "Common functions file ($common_file) is missing"
#    exit -1
#fi

# my logging function 
myprint(){
	timestamp=`date +%s`
    if [ $# -eq  0 ]
    then
        echo -e "[ERROR][$timestamp]\tMissing string to log!!!"
    else
    	if [ $# -eq  1 ]
		then 
            echo -e "[$0][$timestamp]\t" $1
		else 
            echo -e "[$0][$timestamp][$2]\t" $1
		fi 
    fi
}

# general parameters 
screen_id=3                                  # (virtual) display ID 
curr_dir=`pwd`                               # folder where script is run
log_folder=$curr_dir"/logs"                  # folder where all logs go 
record_screen="False"                        # by default do not record screen
no_vnc_PORT=6082                             # deafult port used by no-VNC
no_vnc_path="./noVNC-1.0.0"                  # path for noVNC tool 
device_id=""                                 # identifier of real device under test
password="!IoTLab2020!"                  # current VNC password 
session_id="testing"                         # session identifier for logging
def_port=5555                                # default port used by adb over wifi
                        
# read input parameters
while [ "$#" -gt 0 ]
do
	case "$1" in
	-s | --screen)
		shift;
		screen_id="$1"
		shift
		;;

	-d | --device)
		shift;
		device_id="$1"
		shift
		;;

	-v | --video)
		shift;
		record_screen="True" 
		shift
		;;

	-p | --port)
		shift;
		no_vnc_PORT="$1" 
		shift
		;;
	
	--id)
		shift;
		session_id="$1" 
		shift
		;;

	-h | --help)
		usage
		;;

	-*)
		myprint "ERROR: Unknown option $1"
		usage
		;;
	esac
done

# folder management 
mkdir -p $log_folder

# log instructions 
myprint "=================================================================================================="
myprint "\tIf asked for password use: $password"
myprint "\tWould you like to enter a view-only password (y/n)? y"
myprint "\t\tEnter same or random password. Not used, but tigervnc 1.9.0 has a bug"
myprint "=================================================================================================="

# restart VNC
x_vnc=500
y_vnc=800
vnc_res=$x_vnc"x"$y_vnc
myprint "Restarting VNC. Screen: $screen_id Size: $vnc_res"
vncserver -kill :$screen_id > /dev/null 2>&1 
tigervncserver :$screen_id -geometry $vnc_res
if [ $? -ne 0 ]
then 
	vncserver :$screen_id
fi 
let "vnc_port = 5900 + screen_id"

#no-VNC restart 
myprint "Starting no-vnc (port: $no_vnc_PORT) pointing to VNC on port: $vnc_port"
for pid in `ps aux | grep "websockify" | grep -v "grep" | grep $vnc_port | awk '{print $2}'`
do 
	kill -9 $pid 
done 
for pid in `ps aux | grep "launch.sh" | grep -v "grep" | awk '{print $2}'`
do 
	kill -9 $pid 
done 
cert_path=$curr_dir"/certificate.pem"
cd $no_vnc_path
if [ -f $cert_path ] 
then 
	myprint "Using TLS" 
	(./utils/launch.sh --vnc localhost:$vnc_port --listen $no_vnc_PORT --cert $cert_path > $log_folder"/noVNC-log-"$session_id".txt" 2>&1 &)
else 
	(./utils/launch.sh --vnc localhost:$vnc_port --listen $no_vnc_PORT > $log_folder"/noVNC-log-"$no_vnc_PORT".txt" 2>&1 &)
fi 
cd - > /dev/null 2>71 

# export display 
export DISPLAY=:$screen_id

# stop if previously running 
for pid in `ps aux | grep 'scrcp\|scrcpy-server.jar' | grep -v "grep" | awk '{print $2}'`
#for pid in `ps aux | grep 'scrcp\|scrcpy-server.jar' | grep -v adb  | grep -v grep | awk '{print $2}'`
do 
	kill -9 $pid 
done
#opt="-s $device_id -b 2M"
opt="-s $device_id -m 640"
if [ $record_screen == "True" ]
then 
	suffix=`date +%s`
	opt=$opt" -r screen-record-$suffix.mp4"
fi 

# start screen mirroring in virtual screen 
(scrcpy $opt > $log_folder/log-$device_id-$session_id.txt 2>&1 &)
#(/home/pi/batterylab/src/setup/scrcpy/x/app/scrcpy $opt > $log_folder/log-phone-$device_id.txt 2>&1 &)

# restart web-app
for pid in `ps aux | grep "web-app.py" | grep -v "grep" | awk '{print $2}'`; do  kill -9 $pid; done
sleep 1
ps aux | grep web-app | grep -v "grep" > /dev/null
if [ $? -eq 1 ]
then
    # folder organization
    mkdir -p  crowdsourcing-results/$session_id
    myprint "Started webapp on port 8080 - log: $log_folder/log-web-app-$session_id.txt"
    (python3 web-app.py $session_id > $log_folder/log-web-app-$session_id.txt 2>&1 &)
else
    myprint "Webapp already running on port 8080. Weird, since it should have been killed"
fi

# all done
url="http://localhost:$no_vnc_PORT/vnc-phone.html" 
myprint "Access device @URL: $url"
