#!/bin/bash
adb uninstall "com.example.sensorexample"
adb push app-debug.apk  /data/local/tmp/
adb shell pm install -t /data/local/tmp/app-debug.apk
