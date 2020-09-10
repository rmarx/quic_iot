#!/bin/bash 
## Author: Matteo Varvello (based on https://www.raspberrypi.org/documentation/configuration/wireless/access-point.md) 
## Date:   11/06/2019
## NOTES:  Script to automate the process of making a pi an access point 

# parameters 
ip_access_point="192.168.8.1/24"
wifi_interface="wlan0"
wifi_freq="2.4Ghz"

# install required packages 
sudo apt install -y dnsmasq hostapd

# stop dnsmasq and hostapd processes (after above, they are running with default config) 
sudo systemctl stop dnsmasq
sudo systemctl stop hostapd

# BatteryLab WiFi Hotspot
echo "" >> /etc/dhcpcd.conf
echo "# IoTLab WiFi Hotspot" >> /etc/dhcpcd.conf
echo "interface $wifi_interface" >> /etc/dhcpcd.conf
echo -e "\tstatic ip_address=$ip_access_point" >> /etc/dhcpcd.conf
echo -e "\tnohook wpa_supplicant" >> /etc/dhcpcd.conf

# restart the dhcp daemon 
sudo service dhcpcd restart

# configure DHCP server (dnsmasq) 
sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
sudo cp dnsmasq.conf /etc/dnsmasq.conf

# reaload dnsmasq
sudo systemctl reload dnsmasq

#Configuring the access point host software (hostapd)
if [ $wifi_freq == "5Ghz" ] 
then 
	sudo cp hostapd-5G.conf /etc/hostapd/hostapd.conf
elif [ $wifi_freq == "2.4Ghz" ] 
then 
	sudo cp hostapd-2.4G.conf /etc/hostapd/hostapd.conf
fi 

# inform hostapd about the new configuration file
cat /etc/default/hostapd | sed s/"#DAEMON_CONF=\"\""/"DAEMON_CONF=\"\/etc\/hostapd\/hostapd.conf\""/ > t 
sudo mv t /etc/default/hostapd

# enable and start hostapd
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl start hostapd

# add routing and masquerade (and make it persistent)
sudo sed -i '/net.ipv4.ip_forward=1/s/^#//g' /etc/sysctl.conf
sudo iptables -t nat -A  POSTROUTING -o eth0 -j MASQUERADE
echo "[wifi-setup.sh] L60 added nat entries also for eventual tun0 interface (in case a VPN is used)"
sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
#sudo sh -c "iptables-save > /etc/iptables.ipv4.nat"

# make the above persistent
sudo cp rc.local /etc/rc.local
