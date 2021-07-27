#!/bin/bash
#filename=`adb shell "ls /storage/emulated/0/Android/data/com.example.accessibilityserviceexample/files/ | tail -n 1"`
filename=`adb shell "ls /storage/emulated/0/Android/data/com.example.sensorexample/files/ | tail -n 1"`
android_file="/storage/emulated/0/Android/data/com.example.sensorexample/files/$filename"
android_local=`echo $android_file | awk -F "/" '{print $NF}'`
cum_file="android-log-new"
adb pull $android_file
adb shell "echo \"\" > $android_file"

# realunch app so to create a new file -- if needed
#adb shell monkey -p com.example.accessibilityserviceexample 1

# derive new size 
wc -l $cum_file
cat $android_local >> $cum_file 
wc -l $cum_file
rm $android_local
last_line=`tail -n 1 $cum_file`
echo "Current Time: `date`" 
echo $last_line | grep "CONNECTION\|MOBILE" > /dev/null 
if [ $? -eq 0 ] 
then 
	val=$((`tail -n 1 $cum_file | cut -f 1`/1000))
	#date -r $((`tail -n 1 $cum_file | cut -f 1`/1000))
	date_val=`date -d @$val`
else 	
	val=$((`tail -n 1 $cum_file | cut -f 1 -d ","`/1000))
	#date -r $((`tail -n 1 $cum_file | cut -f 1 -d ","`/1000))
	date_val=`date -d @$val`
fi 
echo "Last Log Time: $date_val"

# upload results 
#rsync -avz android-log-new pikachu:/home/varvello/quic_iot/iot-intercept/results/1625685803/human/
