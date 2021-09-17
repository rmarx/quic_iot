#!/bin/bash
# NOTE:   Helper to setup protonVPN. Not tested :-) 
# Author: Matteo Varvello (matteo.varvello@nokia.com)

# trap ctrl-c
trap ctrl_c INT
function ctrl_c() {
	myprint "Trapped CTRL-C. Stopping VPN"
	vpn_off
	exit -1
}

# function to make sure VPN is off
vpn_off(){
    for pid in `ps aux | grep "openvpn" | grep -v "grep" | awk '{print $2}'`
    do
        myprint "turning VPN off (PID: $pid)"
        sudo kill -9 $pid
        vpn_was_killed="true"
    done
}

#function to wait for VPN to be ready
wait_for_vpn(){
    MAX_CONN_TIME=30
    t_s=`date +%s`
    myprint "Waiting up to $MAX_CONN_TIME secs for <<Initialization Sequence Complete>>"
    while [ $vpn_ready == "false" ]
    do
        if [ ! -f $1 ]
        then
            echo "VPN-log $1 is missing"
            sleep 3
        fi
        cat $1 | grep "Initialization Sequence Completed"
        ans=$?
        if [ $ans -eq 0 ]
        then
            my_ip=`curl -s https://ipinfo.io/ip`
            vpn_ready="true"
        else
            sleep 1
            t_c=`date +%s`
            let "t_p = t_c - t_s"
            if [ $t_p -gt $MAX_CONN_TIME -a $vpn_ready == "false" ]
            then
                myprint "Timeout detected for $curr_vpn - Aborting"
                break
            fi
        fi
    done
}

# set rules to avoid loosing ssh
keep_ssh(){
    sudo ip rule add from $(ip route get 1 | grep -Po '(?<=src )(\S+)') table 128
    sudo ip route add table 128 to $(ip route get 1 | grep -Po '(?<=src )(\S+)')/32 dev $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)')
    #sudo ip route add table 128 default via $(ip -4 route ls | grep default | grep -Po '(?<=via )(\S+)') # Q: this does not work and not needed.
}

# simple function for logging
myprint(){
    timestamp=`date +%s`
    if [ $DEBUG -gt 0 ]
    then
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
    fi
}

# parameters
open_vpn_file="us-ca-02.protonvpn.com.udp.ovpn"          # openvpn config file, proton provides MANY of those
openvpn_pass="pass.txt"                                  # your keys go here 
log_vpn=".log-vpn"                                       # log used to check if all was good
t_sleep=10                                               # just some time to rest, it is always good to rest :P
vpn_was_killed="false"                                   # flag to keep track of status 
DEBUG=1                                                  # flag for debugging

# read potential input 
if [ $# -eq 1 ] 
then 
	open_vpn_file=$1
	myprint "Updating vpn location to: $open_vpn_file"
fi 

# turn off VPN (if was active)
prev_ip=`curl -s https://ipinfo.io/ip`
vpn_off
my_ip=`curl -s https://ipinfo.io/ip`
myprint "PreviousIP: $prev_ip Current-IP: $my_ip vpn_was_killed: $vpn_was_killed VPN-config-file: $open_vpn_file LogFile: $log_vpn"
if [ $vpn_was_killed == "true" ]
then
    myprint "Sleeping $t_sleep seconds since prvious VPN config was stopped."
    sleep $t_sleep
fi

# check if VPN needs to be turned on or not
ip route show table all | grep "128" > /dev/null 2>&1
if [ $? -eq 1 ] 
then 
	myprint "Adding rules to make sure local SSH to the pi is not broken"
	keep_ssh
fi 

# VPN setup
vpn_ready="false"
(sudo openvpn --config $open_vpn_file  --auth-user-pass $openvpn_pass > $log_vpn 2>&1 &)
wait_for_vpn $log_vpn
if [ $vpn_ready == "false" ]
then
    myprint "Error setting up VPN"
    exit -1 
fi
my_ip=`curl -s https://ipinfo.io/ip`
myprint "New IP: $my_ip" 

# monitor VPN over time
echo "true" > ".to_monitor"
to_monitor=`cat ".to_monitor"`
while [ $to_monitor == "true" ] 
do 
	ifconfig | grep "tun" > /dev/null 2>&1 
	is_tun_up=$?
	ps aux | grep "openvpn" | grep -v "grep" > /dev/null 2>&1
	is_openvpn_up=$?
	myprint "[Status] is_tun_up:$is_tun_up is_openvpn_up:$is_openvpn_up"
	if [ $is_tun_up -ne 0 -o  $is_openvpn_up -ne 0 ] 
	then 
		prev_ip=`curl -s https://ipinfo.io/ip`
		vpn_off
		vpn_ready="false"
		(sudo openvpn --config $open_vpn_file  --auth-user-pass $openvpn_pass > $log_vpn 2>&1 &)
		wait_for_vpn $log_vpn
		if [ $vpn_ready == "false" ]
		then
    		myprint "Error setting up VPN"
		    exit -1 
		fi
		my_ip=`curl -s https://ipinfo.io/ip`
		myprint "[VPN-RESTORE] PreviousIP: $prev_ip Current-IP: $my_ip"
	else 
		sleep 60 
	fi 
	to_monitor=`cat ".to_monitor"`
done 

# all done
myprint "All done!" 
