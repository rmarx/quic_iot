#!/bin/bash 
## Notes: Common functions across cripts 
## Author: Matteo Varvello (Brave Software)
## Date: 04/10/2019

# import util file
DEBUG=1
util_file=$base_dir"/util.cfg"
if [ -f $util_file ]
then
    source $util_file
else
    echo "Util file $util_file is missing"
    exit 1
fi

# absolute path 
curr_dir=$HOME"/batterylab/src/automation"
log_folder=$HOME"/batterylab/src/remote-access/logs"
#curr_dir=$HOME"/WorkBrave/batterylab/src/automation"
#log_folder=$HOME"/WorkBrave/batterylab/src/remote-access/logs"
screen_id=3
def_port=5555

# fixing  uhubctl PATH so it is callable by jenkins
uhubctl_PATH="/home/pi/batterylab/src/setup/uhubctl"

# read XML file
read_dom () {
    local IFS=\>
    read -d \< ENTITY CONTENT
}

#identify device id (learn if USB or wifi is used)
identify_device_id(){
	# by default we assume USB over cable, if not we adapt
	device_id=$adb_identifier

	# check device-id exists
	usb_status="online"
	adb devices | grep $device_id > /dev/null
	if [ $? -ne 0 ]
	then
		myprint "WARNING -- The requested device ($device_id) is not reachable via USB."
		# relaxing cause sometimes u want to do so (especially now that wifi is more stable) 
		#if [ $use_monsoon == "false" ]
		#then
		#	myprint "[ERROR] ADB over USB should be used when Monsoon is off"
		#	exit 1
		#fi
		usb_status="offline"
	fi

	# check if adb over wifi is even possible
	adb devices | grep $device_ip > /dev/null
	if [ $? -eq 0 ]
	then
		wifi_status='connected'
		device_id=$device_ip":"$def_port
		myprint "[INFO] Using ADB over wifi..."
	else
		wifi_status='offline'
	fi

	# logging
	myprint "[INFO] [Device] Name: $device USB-id: $adb_identifier  IP: $device_ip - MAC: $device_mac - WifiStatus: $wifi_status USBStatus: $usb_status Screen-res: $screen_res"

	# check device and connection (usb vs wifi) status [REWRITE BETTER LOGIC]
	if [ $wifi_status == "offline" ]
	then
		if [ $use_monsoon == "true" ]
		then
			if [ $usb_status == "online" ]
			then
				myprint "[WARNING] USB is active and you requested to use monsoon. Switching to wifi!"
				detect_USB_info
				enable_adb_wifi $usb_device_id
				#enable_adb_wifi $usb_device_id $usb_hub $usb_port
				device_id=$device_ip":"$def_port
			else
				myprint "[ERROR] Monsoon requested but adb is not available either over USB or wifi"
				exit 1
			fi
		else
			if [ $usb_status == "offline" ]
			then
				myprint "[ERROR] Device unreachable via USB"
				exit 1
			fi
			myprint "[WARNING] running using USB connection"
		fi
	else
		device_id=$device_ip":"$def_port
	fi
}

# verify that wifi works
wifi_test(){
	wifi_work="false"
	myprint "Checking that wifi works (i.e., status of device via its mac: $device_mac)"
	sudo iw dev wlan0 station dump | grep -A 18 $device_mac > .wifi-status
	if [ $? -eq 1 ]
	then
		myprint "ERROR - Device not connected to batterylab wifi"
		return 1
	fi
	authorized=`cat .wifi-status | grep "authorized" | awk '{print $NF}'`
	authenticated=`cat .wifi-status | grep "authenticated" | awk '{print $NF}'`
	associated=`cat .wifi-status | grep "authorized" | awk '{print $NF}'`
	if [ $authorized == "yes" -a $authenticated == "yes" -a $associated == "yes" ]
	then
		myprint "WIFI status: OK!"
		return 0 
	else
		myprint "ERROR - Problem with wifi. Device not authorized/authenticated/associated. Check <<systemctl status create_ap>>?"
		return 1
	fi
}

# compute bandwidth consumed (delta from input parameter)
compute_bandwidth(){
	prev_traffic=$1
    
	# for first run, just report on current traffic	
	curr_traffic=`adb -s $device_id shell cat /proc/net/xt_qtaguid/stats | grep $interface | grep $uid | awk '{traffic += $6}END{print traffic}'`
    myprint "[INFO] Current traffic rx by $app: $curr_traffic"
    if [ -z $prev_traffic ]
    then
		traffic="-1"
		return -1
	fi 

    if [ -z $curr_traffic ]
    then
        myprint "[ERROR] Something went wrong in bandwidth calculcation"
		traffic="-1"
		return -1
	fi 
	traffic=`echo "$curr_traffic $prev_traffic" | awk '{traffic = ($1 - $2)/1000000; print traffic}'` #MB
	if [ ! -z $traffic ]
	then
		#myprint "[INFO] App: $app Bandwidth: $traffic MB"
		#log_traffic=$rep_folder"/traffic-"$rep".txt"
		echo $traffic  > $log_traffic
	else
		echo "0"  > $log_traffic
		myprint "[ERROR] Something went wrong in traffic analysis"
	fi
}

# monitor CPU usage using TOP 
cpu_monitor_top(){
    sleep_time=3
    to_monitor="true"

    if [ $app == "zoom" ]
    then 
        key="zoom"
    elif [ $app == "meet" ]
    then 
        key="com.google.and"
    elif [ $app == "webex" ]
    then
        key="webex"
    fi 
    
    # logging 
    myprint "Start monitoring CPU via TOP (PID: $$)"
                    
    # clean cpu sync barrier done via files 
    if [ -f ".ready_to_start" ] 
    then 
        rm ".ready_to_start"
    fi 

    # continuous monitoring
    while [ $to_monitor == "true" ]
    do
        adb -s $device_id shell top -n 1 | grep $key >> $log_cpu_top
        sleep $sleep_time
        to_monitor=`cat .to_monitor`
    done        

    # logging
    myprint "Done monitoring CPU via TOP (PID: $$)"
}


# monitor cpu
cpu_monitor(){
    sleep_time=3
    prev_total=0
    prev_idle=0
    first="true"
    stable=0
    started="false"
    t1=`date +%s`
    to_monitor="true"
	
	# logging 
	myprint "Start monitoring CPU (PID: $$)"
					
	# clean cpu sync barrier done via files 
	if [ -f ".ready_to_start" ] 
	then 
		rm ".ready_to_start"
	fi 

    # decide low CPU threshold
    LOW_CPU=10
    remote_access="false" #FIXME -- this needs to be dynamic
    if [ $remote_access == "true" ]
    then
        let "LOW_CPU = LOW_CPU + 10"
    fi

    # continuous monitoring
    while [ $to_monitor == "true" ]
    do
        result=`adb -s $device_id shell cat /proc/stat | head -n 1 | awk -v prev_total=$prev_total -v prev_idle=$prev_idle '{idle=$5; total=0; for (i=2; i<=NF; i++) total+=$i; print (1-(idle-prev_idle)/(total-prev_total))*100"%\t"idle"\t"total}'`
        cpu_util=`echo "$result" | cut -f 1 | cut -f 1 -d "%"`
        prev_idle=`echo "$result" | cut -f 2`
        prev_total=`echo "$result" | cut -f 3`
        t_current=`date +%s`
        let "time_passed = t_current - t1"
        if [ $first == "false" ]
        then
            # nothing to do if users do not care about low CPU requirement 
            #if [ $use_monsoon != "true" ]
			if [ $low_cpu != "true" ] 
            then
                echo -e $time_passed"\t"$result"\tN/A" >> $log_cpu
                sleep $sleep_time
                to_monitor=`cat .to_monitor`
                continue
            fi

            # assert if we are stable enough for starting a test
			if [ $started == "false" ] 
			#if [ $started == "true" ] 
			then 
				cpu_util_int=`echo $cpu_util | cut -f 1 -d "."`
				if [ $cpu_util_int -le $LOW_CPU ]
				then
					let "stable++"
					myprint "LOW_CPU ($cpu_util_int% <= $LOW_CPU%) detected $stable consecutive times"
					if [ $stable -ge 3 ]
					then
						if [ $started == "false" ]
						then
							myprint "CPU barrier passed. Experiment is ready to start."
							echo "READY" > ".ready_to_start"
							started="true"
						fi
					fi
				else
					myprint "CPU barrier not passed ($cpu_util_int >= $LOW_CPU%)"
					stable=0
				fi
			fi 

            # logging
            echo -e $time_passed"\t"$result >> $log_cpu
        fi
        first="false"
        sleep $sleep_time
        to_monitor=`cat .to_monitor`
    done

    # logging
	myprint "Done monitoring CPU (PID: $$)"
}

# function to load workload to be used
load_workload(){
    declare -ag W2 # global URLs array
    limit=$1       # target number of websites (provide high number if no limit)
    mode="classic"
	if [ $# -gt 1 ] 
	then 
		myprint "changing workload as per specific request: $2"
		mode=$2
	fi 

    # CHECK this # FIXME
    hex_mode=`echo $mode | cut -f 1 -d "#"`
    hex_code=`echo $mode | cut -f 2 -d "#"`
    workload_info=$curr_dir"/workload.txt"
    if [ ! -f $workload_info ]
    then
        myprint "File <<workload.txt>> is required!"
        exit 1
    fi
    c=0
    line=`cat $workload_info | grep $mode`
    for i in $(echo "$line" | cut -f 3 | sed "s/,/ /g")
    do
        W2[$c]=$i
        let "c++"
        if [ $c -ge $limit ]
        then
            myprint "Limit reached for $mode ($c URLs to be tested)"
            break
        fi
    done
    numURLs=$c
}

# stop monsoon data collection
stop_battor(){
    if [ $use_battor == "true" ]
	then 
		# stop streaming data
		myprint "Stop streaming battor data..."
        battor -k
		
		# stop background process
		for pid in `ps aux | grep "battor -s" | grep -v grep  | awk '{print $2}'`
		do 
			kill -9 $pid 
		done

        # verify buffering stopped
        val=`battor -o 2>/dev/null`
        if [ $val -ne 0 ]
        then
            myprint "[ERROR] Something went wrong when stopping battor"
        else
            myprint "[INFO] Battor was successfully stopped"
        fi
    fi
}

# stop monsoon data collection
stop_monsoon(){
    if [ $use_monsoon == "true" ]
    then
        t_current=`date +%s`
        let "dur = t_current - t_start_monsoon"
        myprint "Stopping monsoon. Duration: $dur"
        for pid in `ps aux | grep "collect-power-measurements.py" | grep -v "grep" | grep -v "vi" | awk '{print $2}'`
        do
            sudo kill -9 $pid
        done
    fi
}

# function to leverage monsoon data colection
monsoon_data_collect(){
    #monsoon_log=$rep_folder"/monsoon-log-$rep.csv"
    monsoon_path=$HOME"/batterylab/src/monsoon"

    myprint "Stop potentially pending processes collecting power measurements" 
	for pid in `ps aux | grep "collect-power-measurements.py" | grep -v "grep" | awk '{print $2}'`; do  sudo kill -9 $pid ; done

    myprint "Starting monsoon data collection: $monsoon_log"
    (sudo python3 -u $monsoon_path"/collect-power-measurements.py" -1 $monsoon_log > monsoon-log.txt 2>&1 &)
}

# function to low currently supported browsers
log_supported_browsers(){
    c=0
    for key in "${!dict_packages[@]}"
    do
        if [ $c -eq 0 ]
        then
            str="["$key
            let "c++"
        else
            str=$str", "$key
        fi
    done
    str=$str"]"
    myprint "[ERROR] Browser $app is not supported. Current supported browsers are: $str"
    exit 1
}

# function to load package and activity info per supported browser
#load_browser(){
#	echo "load_browser"
#    # FIXME -- path
#    if [ ! -f $curr_dir"/browser-config.txt" ]
#    then
#        echo "[ERROR] File browser-config.txt is needed and it is missing"
#        exit 1
#    fi
#    while read line
#    do
#        browser=`echo -e  "$line" | cut -f 1`
#        package=`echo -e  "$line" | cut -f 2`
#        activity=`echo -e "$line" | cut -f 3`
#		echo "$browser $package $activity"
#        dict_packages[$browser]=$package
#        dict_activities[$browser]=$activity
#    done < $curr_dir"/browser-config.txt"
#}

# extract app information #FIXME -- redo with json 
app_info(){
    package=${dict_packages[$app]}
    activity=${dict_activities[$app]}
    if [ -z $package -o -z $activity ]
    then
        log_supported_browsers
        exit 1
    fi
	browser_vrs=`adb -s $device_id shell dumpsys package $package | grep "versionName" | head -n 1`
    myprint "[INFO] Browser: $app Version: $browser_vrs Browser-options: $app_option Package: $package Activity: $activity"
    adb -s $device_id shell 'pm list packages -f' | grep $package
    if [ $? -eq 1 ]
    then
        myprint "App $app (package: $package) is currently not installed on phone!"
        exit 1
    fi
    uid=`adb -s $device_id shell dumpsys package $package | grep "userId=" | head -n 1 | cut -f 2 -d "="`
}

# function to read phones info via json 
get_device_info(){
	json_file=$1
	device_name=$2
	for line in `jq -c ".[]" $json_file`
	do
		name=`echo $line | jq .name | sed s/"\""//g`
		ip=`echo $line | jq .ip | sed s/"\""//g`
		adb_identifier=`echo $line | jq .adb_identifier | sed s/"\""//g`
		if [ $name == $device_name -o $ip":5555" == $device_name -o $adb_identifier == $device_name ]
		then
			screen_res=`echo $line | jq .screen_res | sed s/"\""//g`
			voltage=`echo $line | jq .voltage | sed s/"\""//g`
			gpio_pin=`echo $line | jq .gpio_pin | sed s/"\""//g`
			channel=`echo $line  | jq .channel | sed s/"\""//g`
			mac_address=`echo $line | jq .mac_address | sed s/"\""//g`
			device_os=`echo $line | jq .os | sed s/"\""//g`
			device_wifi=`echo $line | jq .wifi | sed s/"\""//g`
			if [ $device_os == "ios" ] 
			then 
				mac_bluetooth=`echo $line | jq .bluetooth_mac | sed s/"\""//g`
			fi 
			#echo "$adb_identifier $ip $screen_res $voltage $gpio_pin $mac_address $channel $device_os"
			break 
		fi
	done
}

# get device name from adb identifier
get_device_name(){
	json_file=$1
	device_id=$2
	h=`hostname | cut -f 2 -d "-"`
	for line in `jq -c ".[]" $json_file`
	do
		node=`echo $line | jq .node | sed s/"\""//g`
		if [[ $node == *"$h"* ]]
		then
			adb_identifier=`echo $line | jq .adb_identifier | sed s/"\""//g`
			wifi_identifier=`echo $line | jq .ip | sed s/"\""//g`":5555"    #CAREFUL: hardcoded port can cause bugs
			if [ $adb_identifier == $device_id -o $wifi_identifier == $device_id ]
			then
				name=`echo $line | jq .name | sed s/"\""//g`
				return 0 
			fi 
		fi 
	done
	return 1 
}

# get device name from adb identifier
get_device_name_from_channel(){
	json_file=$1
	device_channel=$2
	h=`hostname | cut -f 2 -d "-"`
	for line in `jq -c ".[]" $json_file`
	do
		node=`echo $line | jq .node | sed s/"\""//g`
		if [[ $node == *"$h"* ]]
		then
			channel=`echo $line | jq .channel | sed s/"\""//g`
			if [ $channel == $device_channel ]
			then
				name=`echo $line | jq .name | sed s/"\""//g`
				break 
			fi 
		fi 
	done
}


# function to control relay switching
relay_switch(){
    # FIXME -- move this somewhere else where it is read from a config file
	pi_pins[0]=7
    pi_pins[1]=8
    pi_pins[2]=9
    pi_pins[3]=15
  	target=$1      # target of relay switch
	d=$2           # device
	pin=$3         # pin to be used 

	# switch from monsoon to battery
	if [ $target == "mon-to-batt" ]
	then 
    	echo "activating battery - device: $d pi-pin: $pin"
		state="1"
	# switch from battery to monsoon
	elif [ $target == "batt-to-mon" ]
	then 
	 	echo "activating monsoon bypass - device: $d pi-pin: $pin"
		state="0"
	else 
		echo "command not supported yet"
		return 1
	fi 

	#switch circuit to add monsoon bypass
    num_relay_pins=${#pi_pins[@]}
    for ((p=0; p<num_relay_pins; p++))
    do
        current_pin=${pi_pins[$p]}
        if [ $current_pin -eq $pin ]
        then
			#gpio mode $current_pin out
            gpio write $current_pin $state
        else
			#gpio mode $current_pin out
            gpio write $current_pin 1
        fi
    done

	# all good 
	return 0 
}

# helper to detect USB info of phone under test 
detect_USB_info(){
	echo "WARNING - Always activating port 2 on 1-1 since it is like a master hub"
	sudo env "PATH=$uhubctl_PATH" uhubctl -a on -l 1-1 -p 2 
	sudo env "PATH=$uhubctl_PATH" uhubctl  > .sub-info 2>/dev/null 
	while read line 
	do
		# check if line contains hub info or port info 
		echo "$line" | grep "hub" | grep "status" > /dev/null
		if [ $? -eq 0 ] 
		then 
			# keep track of current hub 
			usb_hub=`echo "$line" | awk '{print $5}'`
			echo "Current USB hub: $usb_hub"
		else 
			# parse line with port information
			usb_port=`echo "$line" | awk '{print $2}' | cut -f 1 -d ":"`
			port_status=`echo "$line" | awk '{print $4}'`

			# turn ON if needed to check if device is there 
			if [ $port_status == "off" ] 
			then 
				echo "Activating port $usb_port (hub: $usb_hub) to see if phone $device_id is connected there"
				echo "sudo env \"PATH=$uhubctl_PATH\" uhubctl -a on -l $usb_hub -p $usb_port" 
				sudo env "PATH=$uhubctl_PATH" uhubctl -a on -l $usb_hub -p $usb_port > /dev/null 2>&1 
				
				# wait some time for device to come up and check 
				sleep 5 
			
				# iOS issue, but the other seems to give an issue? 
				#adb devices | grep $device_id > /dev/null 
				sudo env "PATH=$uhubctl_PATH" uhubctl | grep $device_id > /dev/null 
				#sudo env "PATH=$uhubctl_PATH" uhubctl -l $usb_port -p $usb_hub | grep $device_id > /dev/null 
				if [ $? -eq 0 ]
				then
					echo "Device $device_id found. Connected on USB port $usb_port (USB hub: $usb_hub)"
					return 0 
				else 
					# turn port OFF if was fonud OFF 
					echo "Device not found. Restoring power OFF on port $usb_port (hub: $usb_hub)"
					sudo env "PATH=$uhubctl_PATH" uhubctl -a off -l $usb_hub -p $usb_port > /dev/null 2>&1
				fi 
			else 
				# check if device under test is connected there
				echo "$line" | grep $device_id  > /dev/null
				if [ $? -eq 0 ]
				then 
					echo "Device $device_id found. Connected on USB port $usb_port (USB hub: $usb_hub)"
					# device correctly found
					return 0 
				fi 
			fi 
		fi 
	done < ".sub-info"

	# device not found (yet) 
	return 1 
}

# specific wifi test for iPhone
iphone_wifi_test(){
    # verify wifi at the controller is right frequency
    if [ $device_wifi == "2.4Ghz" ]
    then
        mode="hw_mode=g"
    elif [ $device_wifi == "5Ghz" ]
    then
        mode="hw_mode=a"
    else
        myprint "ERROR - Wrong wifi frequency in device json file"
        stop_test
    fi
    cat "/etc/hostapd/hostapd.conf" | grep $mode > /dev/null
    if [ $? -eq 1 ]
    then
        myprint "Wrong wifi frequency detected at controller. Updating to $device_wifi ($mode)"
        ../setup/wifi-update.sh $device_wifi
        sleep 10
    fi

    # verify that wifi works
    attempt=0
    while [ $attempt -lt 3 ]
    do
        wifi_test
        if [ $? -ne 0 ]
        then
            ../setup/wifi-update.sh $device_wifi
            sleep 10
        else
            break
        fi
        let "attempt++"
    done
    if [ $attempt -eq 3 ]
    then
        myprint "serious wifi issue detected"
        stop_test
    fi
}

# wait for phone under test to boot once powered (USB, socket, monsoon) 
# Assumption: when plugged via USB and powered with monsoon, devices should automatically boot 
wait_for_phone(){
	is_booted="false"
	t_start=`date +%s`
	time_passed=0
	TIMEOUT=120
	
	if [ $device_os == "ios" ]
	then
		let "TIMEOUT += 60"
	fi 
	echo "Waiting up to $TIMEOUT seconds for device $device_id (os: $device_os) to boot" 
	while [ $is_booted == "false" -a $time_passed -le $TIMEOUT ] 
	do 
		# check if device is ON 
		if [ $device_os == "android" ]
		then
			adb devices | grep $adb_identifier
			ret_code=$?
		elif [ $device_os == "ios" ]
		then
			(sudo python3 -u ../bt-automation/btk_server/btk_server.py -m connect -d $mac_bluetooth > log-bluetooth.txt 2>&1 &)
			sleep  10
			ps aux | grep "btk_server.py" | grep $mac_bluetooth | grep -v "grep" > /dev/null
			ret_code=$?
			myprint "btk_server.py check - ret_code: $ret_code"
		else 
			myprint "WARNING - OS $device_os not supported yet"
			return 1 
		fi 
		if [ $ret_code -eq 0 ]
		then
			is_booted="true"
			if [ $device_os == "ios" ]
			then
				myprint "Unlocking phone via its PIN..."
				sleep 5
				python3 ../bt-automation/btk-control.py -ud
			fi 
		else 
			# rate control 
			if [ $device_os == "android" ]
			then
				sleep 5
			fi 
		fi

		# update time passed 
		curr_time=`date +%s`
		let "time_passed = curr_time - t_start"
	done 

	# interrupt experiment if device was not found 
	if [ $time_passed -gt $TIMEOUT ]  
	then 
		myprint "[ERROR] Device $device_id did not boot within timeout ($TIMEOUT)"
		return 1 
	fi 
	
	# all good
	myprint "Device $device_id is up! (Took $time_passed to find)"
	return 0 
}

# switch screen-casting
switch_screen(){
	# param 
	found_screen="false"

	# kill pending screencasting
    for pid in `ps aux | grep 'scrcp\|scrcpy-server.jar' | grep -v "adb"  | grep -v "grep" | awk '{print $2}'`
    do
        kill -9 $pid
		found_screen="true"
    done

	# restart screencasting on wifi if a pending one was found 
	if [ $found_screen == "true" ] 
	then 
	    opt="-s $1 -b 2M"
	    export DISPLAY=:$screen_id
		myprint "Switching screencasting to device $device_id"
	    (scrcpy $opt > $log_folder/log-phone-$device_id.txt 2>&1 &)
	fi 
}

# enable adb over wifi for phone under test 
enable_adb_wifi(){
	# logging 
	id=$1
	#usb_hub=$2
	#usb_port=$3
	echo "Enabling adb over wifi -- ID: $id"

	# open port on phone 
	# NOTE -- if rooted, this can be avoided: adb -s 54524a5441573398 shell setprop persist.adb.tcp.port 5555
	max_attempt_time=60
	t1=`date +%s`
	t_p=0
	found="false"
	while [ $t_p -lt $max_attempt_time ] 
	do 
		adb devices | grep $device_ip:$def_port > /dev/null
		if [ $? -eq 0 ]
		then
			echo "Time passed: $t_p Device $device_ip:$def_port found"
			found="true"
			break
		else
			echo "Time passed: $t_p --> adb -s $id tcpip $def_port"
			adb -s $id tcpip $def_port
			sleep 2
			adb connect $device_ip:$def_port
		fi
		t2=`date +%s`
		let "t_p = t2 - t1"
	done
	
	# check if found or not 
	if [ $found == "false" ] 
	then 
		echo "ERROR: wifi could not be enabled"
		return 1 
	fi 

	# disconnect the device - turn off USB 
	#echo "Disconnecting $id by turning off USB (port: $usb_port hub: $usb_hub)" 
	#sudo env "PATH=$uhubctl_PATH" uhubctl -a off -l $usb_hub -p $usb_port > /dev/null 2>&1

	# all good 
	return 0
}

# function to populate device info -- deprecated 
device_info(){

	# warning
	echo "WARNING -- This function is deprecated, you really should not be using it"

	# populate device information
	phones_info=$curr_dir"/phones-info.txt"
	if [ ! -f $phones_info ]
	then
		echo "File <<phones-info.txt>> is required!"
		exit 1
	fi
	while read line
	do
		device_name=`echo "$line" | cut -f 1`
		device_id=`echo "$line" | cut -f 2`
		device_ip=`echo "$line" | cut -f 3`
		device_screen=`echo "$line" | cut -f 4`
		device_voltage=`echo "$line" | cut -f 5`
		device_pin=`echo "$line" | cut -f 6`
		dict_ids["$device_name"]="$device_id"
		dict_ips["$device_name"]="$device_ip"
		dict_screen["$device_name"]="$device_screen"
		dict_volt["$device_name"]="$device_voltage"
		dict_pins["$device_name"]="$device_pin"
	done < "$phones_info"
}

# function to load package and activity info per supported browser
load_browser(){
    if [ ! -f $curr_dir"/browser-config.txt" ]
    then
        echo "[ERROR] File browser-config.txt is needed and it is missing"
        exit 1
    fi
    while read line
    do
        b=`echo -e  "$line" | cut -f 1`
        p=`echo -e  "$line" | cut -f 2`
        a=`echo -e "$line" | cut -f 3`
        dict_packages[$b]=$p
        dict_activities[$b]=$a
    done < $curr_dir"/browser-config.txt"
}
