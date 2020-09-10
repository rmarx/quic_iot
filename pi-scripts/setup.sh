#!/bin/bash 
## NOTE: script to setup the controller for IoTLab
## AUTHOR: Matteo Varvello
## DATE:  09/10/2020

# general parameters 
curr_folder=`pwd`

# install noVNC 
no_vnc_folder="noVNC-1.0.0"
if [ ! -d $no_vnc_folder ] 
then 
	wget https://github.com/novnc/noVNC/archive/v1.0.0.tar.gz
	tar xzvf v1.0.0.tar.gz
else 
	echo "noVNC already installed. Nothing to do" 
fi 
mkdir $no_vnc_folder"/css"

# install and setup tigervnc 
hash tigervncserver > /dev/null 2>&1 
if [ $? -eq 1 ]
then 
	echo "WARNING -- Skipping tigervnc 1.8 (available on buster) due to rdr::EndOfStream bug. 1.10 was released 11/2019, update when a package is released" 
	wget http://ftp.us.debian.org/debian/pool/main/t/tigervnc/tigervnc-standalone-server_1.7.0+dfsg-7_armhf.deb -O tigervnc.deb
	sudo dpkg -i tigervnc.deb
else 
	echo "tigervncserver already installed. Nothing to do."
fi 

# update xstartup file 
mkdir -p $HOME"/.vnc" 
cp xstartup $HOME"/.vnc"

# install adb
hash adb > /dev/null 2>&1 
if [ $? -eq 1 ]
then
	sudo apt-get install -y android-tools-adb
else 
	echo "adb is already installed" 
fi 

# install scrcpy (Android mirroring)
hash scrcpy > /dev/null 2>&1
if [ $? -eq 1 ]
then
	# get the code 
	git clone https://github.com/Genymobile/scrcpy
	
	# runtime dependencies
	sudo apt install -y ffmpeg libsdl2-2.0.0

	# client build dependencies
	sudo apt install -y make gcc pkg-config meson ninja-build \
                 libavcodec-dev libavformat-dev libavutil-dev \
                 libsdl2-dev

	# server build dependencies
	sudo apt install -y openjdk-8-jdk 
	
	# compile prebuild 
	cd scrcpy
	curr_dir=`pwd`
	if [ -d "x" ] 
	then 
		rm -rf "x"
	fi 	
	jar_url=`cat BUILD.md  | grep "scrcpy-server" | grep "http" | cut -f 2 -d " "`
	scrcpy_jar_file="scrcpy-server.jar"
	echo "Using pre-server built: $jar_url"
	wget $jar_url -O $scrcpy_jar_file
	meson x --buildtype release --strip -Db_lto=true -Dprebuilt_server=$curr_dir"/"$scrcpy_jar_file
	cd x 
	ninja 
	sudo ninja install
	cd - > /dev/null 2>&1 
else 
	echo "scrcpy (Android mirroring) already installed. Nothing to do"
fi 


# install cherrypy
hash pip3 > /dev/null 2>&1
if [ $? -eq 1 ]
then
	sudo apt-get install -y python3-pip
fi
sudo pip3 install CherryPy==17.4
