#!/usr/local/bin/bash 
## Notes: Collection of abd utils 
## Author: Matteo Varvello (Brave Software) 
## Date: 02/04/2019

# common parameters
DEBUG=1
wemo_ip="192.168.1.202"
wemo_port="49153"
screen_brightness=70     # default screen brightness

# import common file
common_file=$base_dir"/common.sh"
if [ -f $common_file ]
then
	source $common_file
else
	echo "Common file $common_file is missing"
	exit -1
fi

# helper funtion to  perform a tap
tap_screen(){
    x=$1
    y=$2
    if [ $# -eq 3 ]
    then 
    	t=$3
    fi 
    adb -s $device_id shell "input tap $x $y"
    if [ $# -eq 3 ]
    then     
    	sleep $t
    fi 
}

# check wifi connection at device, and try to fix
verify_wifi(){
    adb -s $device_id shell dumpsys wifi | grep "Wi-Fi is enabled"
    if [ $? -eq 0 ]
    then
        myprint "Wifi is ON"
    else
        myprint "Wifi is OFF, attempt to turn ON"
        toggle_wifi
        adb -s $device_id shell dumpsys wifi | grep "Wi-Fi is enabled"
        if [ $? -eq 0 ]
        then
            myprint "Wifi is ON"
        else
            myprint "ERROR - Wifi is OFF and not coming up"
            exit 1
        fi
    fi
}

# OFF to ON and viceversa
toggle_wifi(){
    adb -s $device_id shell "input keyevent KEYCODE_HOME"
    x_coord=`echo $screen_res | cut -f 1 -d "x" | awk '{print $1/2}'`
	y_coord=`echo $screen_res | cut -f 2 -d "x" | awk '{print $1/2}'`
	adb -s $device_id shell input swipe $x_coord 0 $x_coord $y_coord
    # Q: can we generalize here?
    if [ $device == "SM-J337A" ]
    then
        adb -s $device_id shell "input tap 40 118"
    elif [ $device == "LM-X210" ]
	then 
		adb -s $device_id shell "input tap 175 132"
    elif [ $device == "J7DUO" ]
	then 
		echo "adb -s $device_id shell \"input tap 27 186\""
		adb -s $device_id shell "input tap 27 186"
    elif [ $device == "E5PLAY" ]
	then 
		adb -s $device_id shell "input tap 198 82"
	fi 
    adb -s $device_id shell "input keyevent KEYCODE_HOME"
	sleep 5 
}

# test wifi connectivity at both device and controller and attempt fixe
wifi_full_test(){
	# verify wifi is on at the device
	verify_wifi

	# verify wifi at the controller is right frequency
	if [ $device_wifi == "2.4Ghz" ] 
	then 
		mode="hw_mode=g"
	elif [ $device_wifi == "5Ghz" ] 
	then 
		mode="hw_mode=a"
	else 
		myprint "ERROR - Wrong wifi frequency in device json file" 
		exit 1 
	fi 
	cat "/etc/hostapd/hostapd.conf" | grep $mode
	if [ $? -eq 1 ] 
	then 
		myprint "Wrong wifi frequency detected at controller. Updating to $device_wifi ($mode)"
		../setup/wifi-update.sh $device_wifi
		sleep 10 
	fi 	

	# check wifi status at the controller (potentially reset)
	wifi_status="testing"
	attempt=0
	MAX_ATTEMPTS=5
	while [ $wifi_status != "ready" -a $attempt -lt $MAX_ATTEMPTS ]
	do
		wifi_test
		if [ $? -eq 0 ]
		then
			wifi_status="ready"
		else
			let "t_sleep = 10 + 2*attempt"
			myprint "Wifi issue detected. Reset wifi at controller (Attempt $attempt). Frequency: $device_wifi Time allowed to reconnect: $t_sleep sec"
			../setup/wifi-update.sh $device_wifi
			let "attempt++"
			sleep $t_sleep
		fi
	done
	if [ $attempt -eq $MAX_ATTEMPTS ]
	then
		# reset wifi
		toggle_wifi
		sleep 10
		verify_wifi
		sleep 10
		
		# re-run the test 
		wifi_test
		if [ $? -ne 0 ] 
		then 
			myprint "ERROR - Wifi full test"
			exit 1 
		fi 
	else
		myprint "Wifi full test was succesful!!"
		return 0
	fi
}

# emulate user interaction with a page
page_interact(){
    s_time=`date +%s`
    duration=$1
    num_down=2
    num_up=1
    #num_down=4
    #num_up=2
    t_p=0
	sleepDone="false"
    myprint "interaction with page start: $s_time"
    while [ $t_p -lt $duration ]
    do
        for((i=0; i<num_down; i++))
        do
            #scroll down
            swipe "down" $width $height
            for ((j=0; j<5; j++))
			do 
            	t_current=`date +%s`
				let "t_p = t_current - s_time"
            	if [ $t_p -ge $duration ]
            	then
					sleepDone="true"
                	break
            	fi
            	sleep 1
			done
			if [ $sleepDone == "true" ] 
			then
				break 
			fi 
        done
		if [ $sleepDone == "true" ] 
		then
			break 
		fi 
        for((i=0; i<num_up; i++))
        do
            #scroll up
            swipe "up" $width $height
			for ((j=0; j<5; j++))
			do 
            	t_current=`date +%s`
				let "t_p = t_current - s_time"
            	if [ $t_p -ge $duration ]
            	then
					sleepDone="true"
                	break
            	fi
            	sleep 1
			done
			if [ $sleepDone == "true" ] 
			then
				break 
			fi 
        done
    done

    # logging
    e_time=`date +%s`
    let "time_passed = e_time - s_time"
    let "ts = e_time - t_start_sync"
    myprint "[INFO] Interaction with page end: $e_time. Interaction-duration: $time_passed"
}


# swipe up or down 
swipe(){
	movement=$1
	width=$2
	height=$3
	t1=`date +%s`
	let "x_coord = widht/2"
	if [ $movement == "down" ] 
	then 
		let "start_y = height/2"
		#end_y=100
		end_y=300
	elif [ $movement == "up" ] 
	then 
		#start_y=100
		start_y=300
		let "end_y = height/2"
	else 
		myprint "ERROR - Option requested ($1) is not supported"
	fi 
	
	# execute the swipe 
	adb -s $device_id shell input swipe $x_coord $start_y $x_coord $end_y
	echo "adb -s $device_id shell input swipe $x_coord $start_y $x_coord $end_y"

	# log duration
	t2=`date +%s`
	let "tp = t2 - t1"
	myprint "[INFO] Scrolling $movement. Duration: $tp"
}

#make sure device is ON 
turn_device_on(){	
	is_on="false"
	num_tries=0
	max_attempts=5
	ans=-1
	
	while [ $is_on == "false" -a $num_tries -lt $max_attempts ]
	do
		adb -s $device_id shell dumpsys window | grep mAwake=false
		#adb -s $device_id shell dumpsys window | grep mAwake=false > /dev/null
		if [ $? -eq 0 ]
		then
			myprint "Screen was OFF. Turning ON (Attempt $num_tries/$max_attempts)"
			adb -s $device_id shell "input keyevent KEYCODE_POWER"
		else
			myprint "Screen is ON. Nothing to do!"
			is_on="true"
			ans=0
		fi
		let "num_tries++"
	done

	# return status 
	return $ans
}

# turn device off
turn_device_off(){
    adb -s $device_id shell dumpsys window | grep "mAwake=false"
    if [ $? -eq 0 ]
    then
        myprint "Screen was OFF. Nothing to do"
    else
        sleep 2
        myprint "Screen is ON. Turning off"
        adb -s $device_id shell "input keyevent KEYCODE_POWER"
    fi
}

# close all pending applications 
close_all(){
	# logging 
	dev_model=`adb -s $device_id shell getprop ro.product.model | sed s/" "//g`
	myprint "[CLOSE_ALL] Closing all pending applications for device: $dev_model"

	# go HOME 
	adb -s $device_id shell "input keyevent KEYCODE_HOME"

	# enter switch application tab 
	adb -s $device_id shell "input keyevent KEYCODE_APP_SWITCH"
	sleep 2

	# close things based on device 
    if [ $dev_model == "SM-G973U1" ]
	then 
		adb -s $device_id shell "input tap 550 1750"
	elif [ $dev_model == "SM-G960U" ] 
	then 
		adb -s $device_id shell "input tap 520 1700"
	elif [ $dev_model == "SAMSUNG_SM_G920A" ] 
	then 
		adb -s $device_id shell "input tap 705 2450"
	elif [ $dev_model == "SAMSUNG_SM_G900A" ]
	then  
		adb -s $device_id shell "input tap 815 1854"
	elif [ $dev_model == "SAMSUNG_SM_J727A" ]
	then  
		adb -s $device_id shell "input tap 361 1234"
	elif [ $dev_model == "Pixel2" ] 
	then 
		myprint "[WARNING] Pixel2 lack \"Close all\" button. We thus attempt to manually remove 5 apps. If more, need to be re-run. If less, it will wonder in the app menu"
		foreground=`adb -s $device_id shell dumpsys window windows | grep -E 'mCurrentFocus' | cut -d '/' -f1 | sed 's/.* //g'`
		while [ $foreground == "com.android.systemui" ] 
		do 
			adb -s $device_id shell input swipe 500 800 500 100
			sleep 3 
			foreground=`adb -s $device_id shell dumpsys window windows | grep -E 'mCurrentFocus' | cut -d '/' -f1 | sed 's/.* //g'`
		done
	elif [ $dev_model == "SM-J720F" ] 
	then 
		myprint "pressing close all" 
		adb -s $device_id shell "input tap 360 1019"
	elif [ $dev_model == "Nokia1" ] 
	then 
		adb -s $device_id shell "input tap 413 219"
		sleep 3 
		foreground=`adb -s $device_id shell dumpsys window windows | grep -E 'mCurrentFocus' | cut -d '/' -f1 | sed 's/.* //g'`
		if [ $foreground == "com.android.systemui" ] 
		then 
			adb -s $device_id shell "input tap 240 724"
		fi 
	elif [ $dev_model == "LM-X210" ]
	then 
		adb -s $device_id shell "input tap 360 1116"
	elif [ $dev_model == "SM-J337A" ]
	then 
		adb -s $device_id shell "input tap 368 1224"
	elif [ $dev_model == "motoe5play" ]
	then 
		adb -s $device_id shell "input tap 414 270"
		sleep 3 
		foreground=`adb -s $device_id shell dumpsys window windows | grep -E 'mCurrentFocus' | cut -d '/' -f1 | sed 's/.* //g'`
		if [ $foreground == "com.android.systemui" ] 
		then 
			adb -s $device_id shell "input tap 241 831"
		fi 
	elif [ $dev_model == "SM-J337A" ]
	then 
		adb -s $device_id shell "input tap 375 1220"
	elif [ $dev_model == "RedmiGo" ]
	then 
		adb -s $device_id shell "input tap 360 1210"
	else 
		myprint "[WARNING] Closing of pending apps is not supported yet for model $dev_model"
	fi 
	

	# go back HOME 
	myprint "[CLOSE_ALL] Pressing HOME"
	adb -s $device_id shell "input keyevent KEYCODE_HOME"
}

# setup phone priot to an experiment 
phone_setup_simple(){
	# disable notification 
	myprint "[INFO] Disabling notifications for the experiment"
	adb -s $device_id shell settings put global heads_up_notifications_enabled 0

	# check for airplane mode ON
	myprint "[INFO] Checking for airplane mode"
	is_airplane_mode=`adb -s $device_id shell dumpsys wifi | grep mAirplaneModeOn | grep -i "true" | wc -l`
	if [ $is_airplane_mode != 1 ] 
	then 
		myprint "[WARNING] Consider having phone in airplane mode and wifi enabled only" 
		#exit -1 
	fi 

	# set desired brightness
	myprint "[INFO] Setting screen brightness to $screen_brightness -- ASSUMPTION: no automatic control" 
	adb -s $device_id shell settings put system screen_brightness $screen_brightness

	#get and log some useful info
	dev_model=`adb -s $device_id shell getprop ro.product.model | sed s/" "//g` # S9: SM-G960U
	android_vrs=`adb -s $device_id shell getprop ro.build.version.release`
	myprint "[INFO] DEV-MODEL: $dev_model ANDROID-VRS: $android_vrs"	

	# remove screen timeout 
	max_screen_timeout="2147483647"
	#max_screen_timeout="2147460000"
	adb -s $device_id shell settings put system screen_off_timeout $max_screen_timeout

	# close all pending applications
	close_all

	# all good 
	return 0 
}

# setup phone priot to an experiment 
phone_setup(){
	# input parameters 
	use_vpn=$1
	block_ads=$2
	usb_device_id=$3 
	bright_savings=$4
	if [ $# -gt 4 ] 
	then 
		use_ciao=$5
	fi 
	#check if screen is locked #FIXME: skipping since unreliable across devices 
	#is_locked=`adb shell dumpsys power | grep mHoldingWakeLockSuspendBlocker=true | wc -l`
	#if [ $is_locked -eq 1 ] 
	#then 
	#	myprint "[ERROR] Screen is locked!"
	#	exit -1 
	#fi 
	# input parameters 
	
	# disable notification 
	myprint "[INFO] Disabling notifications for the experiment"
	adb -s $device_id shell settings put global heads_up_notifications_enabled 0

	# check for airplane mode ON
	myprint "[INFO] Checking for airplane mode"
	is_airplane_mode=`adb -s $device_id shell dumpsys wifi | grep mAirplaneModeOn | grep -i "true" | wc -l`
	if [ $is_airplane_mode != 1 ] 
	then 
		myprint "[WARNIG] Consider having phone in airplane mode and wifi enabled only" 
		#exit -1 
	fi 

	# set desired brightness
	myprint "[INFO] Setting screen brightness to $screen_brightness -- ASSUMPTION: no automatic control" 
	adb -s $device_id shell settings put system screen_brightness $screen_brightness

	#get and log some useful info
	dev_model=`adb -s $device_id shell getprop ro.product.model | sed s/" "//g` # S9: SM-G960U
	android_vrs=`adb -s $device_id shell getprop ro.build.version.release`
	myprint "[INFO] DEV-MODEL: $dev_model ANDROID-VRS: $android_vrs"	

	# remove screen timeout 
	#max_screen_timeout="2147460000"
	max_screen_timeout="2147483647"
	adb -s $device_id shell settings put system screen_off_timeout $max_screen_timeout

	# close all pending applications
	close_all

	# all good 
	return 0 
}

# start battery charging if not already charging 
start_charging(){
	wemo_state=`./wemo.sh $wemo_ip:$wemo_port GETSTATE | grep "state" | awk '{print $NF}'`
	if [ $wemo_state == "OFF" ] 
	then 
		./wemo.sh $wemo_ip:$wemo_port ON
		myprint "[INFO] Battery charging started!"
		
		# lower screen brightness 
		myprint "[INFO] Lowering screen brightness to speed up recharge"
		adb -s $device_id shell settings put system screen_brightness 0 
	fi 
}

# recharge battery if needed
battery_recharge(){
	target_battery=$1
	device_id=$2
	battery_level=`adb -s $device_id shell dumpsys battery | grep "level" | awk '{print $2}'`
	t_start=`date +%s`
	t_stabilize=60         # by default we wait one minute after a recharge 

	# control waiting time before recharge 
	if [ $# -eq 3 ] 
	then 
		t_stabilize=$3
	fi 

	# check battery state
	wemo_state=`./wemo.sh $wemo_ip:$wemo_port GETSTATE | grep "state" | awk '{print $NF}'`
	myprint "[INFO] Current battery level: $battery_level Target: $target_battery Recharging-state: $wemo_state Time-to-stabilize: $t_stabilize"
	
	# by default we want battery to be not charging during an experiment
	if [ $wemo_state == "ON" ] 
	then 
		./wemo.sh $wemo_ip:$wemo_port OFF
	fi 

	# check if something need to be done 
	if [ $battery_level -lt $target_battery ] 
	then 
		./wemo.sh $wemo_ip:$wemo_port ON
		myprint "[INFO] Battery recharging started!"
		
		# lower screen brightness 
		myprint "[INFO] Lowering screen brightness to speed up recharge"
		adb -s $device_id shell settings put system screen_brightness 0 
	else 
		myprint "[INFO] Battery is already charged at right level, nothing to be done" 
		return 0
	fi 

	# wait until battery is charged at desired level 
	while [ $battery_level -lt $target_battery ] 
	do
		battery_level=`adb -s $device_id shell dumpsys battery | grep "level" | awk '{print $2}'`
		t_current=`date +%s`
		let "time_passed = t_current - t_start"
		myprint "[INFO] [Time-passed: $time_passed] Battery recharging. Current battery level: $battery_level Target: $target_battery"
		sleep 30 
	done 

	# stop recharging
	./wemo.sh $wemo_ip:$wemo_port OFF
	adb -s $device_id shell settings put system screen_brightness 70
	myprint "[INFO] Battery recharging stopped. Screen brightness resumed to 70 (default value in automate.sh)." 
	
	# allows some time for battery to restabilize after a recharge 
	myprint "[INFO] Sleeping $t_stabilize secs in between recharges..." 
	sleep $t_stabilize
}
