"""
Entry point for Inspector UI.

"""
import logging
import subprocess
import sys
import webbrowser

from arp_scan import ArpScan
from arp_spoof import ArpSpoof
from data_upload import DataUploader
from host_state import HostState
from netdisco_wrapper import NetdiscoWrapper
from packet_capture import PacketCapture
from packet_processor import PacketProcessor
import server_config
from syn_scan import SynScan
import utils


import joblib
import cherrypy
import random
import json
from cherrypy.lib.static import serve_file
import logging
from scapy.all import PcapReader

import fiat_module.utils as fiat_utils
from fiat_module.predictor import Predictor
from fiat_module.fiat_server import FIATHandler, FIATProxyService, CP_CONF
from fiat_module.fiat_server import server_config as fiat_server_config




WINDOWS_STARTUP_TEXT = """

======================================
Princeton IoT Inspector for Windows 10
======================================

We have also opened a new browser window for you to view the IoT Inspector report. If you don't see a new browser window, use the following private link:

{0}/user/{1}

To stop IoT Inspector, simply close this window or hit Control + C.

Questions? Email us at iot-inspector@lists.cs.princeton.edu.

"""


def start():
    """
    Initializes inspector by spawning a number of background threads.
    
    Returns the host state once all background threats are started.
    
    """


    # ------------------------------------- FIAT Handler ------------------------------------ #

    # mode:
    # 0 -> pre-processing data at Android phone
    # 1 -> receiving raw data from phone and processing mean and divation here
    FIAT_MODE = 1
    fiat_auth = FIATHandler(mode=FIAT_MODE, zksense_model='../../zkSENSE/ML/decisiontree7.joblib')

    # -------------------------------------- Predictor ------------------------------------- #

    PREDICTOR = Predictor()

    # --------------------------------------- Main() -------------------------------------- #

    fiat_proxy = FIATProxyService(fiat_auth)
    cherrypy.tree.mount(fiat_proxy, '/', config=CP_CONF)
    cherrypy.tree.mount(fiat_proxy, '/fiatData', config=CP_CONF)
    cherrypy.config.update(fiat_server_config)
    cherrypy.engine.start()
    # cherrypy.quickstart(FIATProxyService(FIAT), '/', CP_CONF)

    # devices = json.load(open(device_file, 'r'))
    devices = [
        {
            "name": "HomeMini", "mac": "30:fd:38:7b:62:51", "ip": "192.168.5.14", 
            "clf": "models/HomeMini.joblib"
        },
        {
            "name": "Wyze", "mac": "2c:aa:8e:15:da:5b", "ip": "192.168.5.15", 
            "clf": "models/WyzeCam.joblib"
        }
    ]
    for de in devices:
        if 'type' in de:
            continue
        PREDICTOR.add_device(**de)

    # Read from home directory the user_key. If non-existent, get one from
    # cloud.
    config_dict = utils.get_user_config()

    utils.log('[MAIN] Starting.')

    # Set up environment
    state = HostState(fiat_auth, PREDICTOR)
    state.user_key = config_dict['user_key'].replace('-', '')
    state.secret_salt = config_dict['secret_salt']
    #state.host_mac = utils.get_my_mac()
    #state.gateway_ip, _, state.host_ip = utils.get_default_route()
    state.has_consent = True
    state.host_mac = "b8:27:eb:e3:3a:e1"
    state.gateway_ip = "192.168.5.1"
    state.host_ip = "192.168.5.7"    

    # Read special command-line arguments
    if '--raspberry_pi_mode' in sys.argv:
        state.raspberry_pi_mode = True

    assert utils.is_ipv4_addr(state.gateway_ip)
    assert utils.is_ipv4_addr(state.host_ip)

    state.packet_processor = PacketProcessor(state)

    utils.log('Initialized:', state.__dict__)

    # Continously discover devices
    arp_scan_thread = ArpScan(state)
    arp_scan_thread.start()

    # Continously discover ports via SYN scans
    #syn_scan_thread = SynScan(state)
    #syn_scan_thread.start()

    # Continuously gather SSDP data
    #netdisco_thread = NetdiscoWrapper(state)
    #netdisco_thread.start()

    # Continuously capture packets
    packet_capture_thread = PacketCapture(state)
    packet_capture_thread.start()

    # Continously spoof ARP
    if '--no_spoofing' not in sys.argv:
        arp_spoof_thread = ArpSpoof(state)
        arp_spoof_thread.start()

    # Continuously upload data
    #data_upload_thread = DataUploader(state)
    #data_upload_thread.start()

    # Suppress scapy warnings
    try:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    except Exception:
        pass

    # Suppress flask messages
    try:
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
    except Exception:
        pass

    # Insert a dash every four characters to make user-key easier to type
    pretty_user_key = ''
    for (ix, char) in enumerate(state.user_key):
        if (ix > 0) and (ix % 4 == 0):
            pretty_user_key += '-'
        pretty_user_key += char

    print('\n' * 100)

    os_platform = utils.get_os()    

    print(WINDOWS_STARTUP_TEXT.format(server_config.BASE_URL, pretty_user_key))

    # Open a Chrome window that runs IoT Inspector since running IoT Inspector
    # on Chrome is preferred. Note that a new webpage will be opened 
    # in non-privileged mode. 

    # For users that do not use chrome, the default browser will be opened in 
    # Windows 10, and Safari will be opened in macOS.

    if os_platform == 'windows' or 'mac':
        url = '{0}/user/{1}'.format(server_config.BASE_URL, pretty_user_key)
        try:
            try:
                webbrowser.get('chrome').open(url, new=2)
            except webbrowser.Error:
                webbrowser.open(url, new=2)
        except Exception:
            pass
    return state


def enable_ip_forwarding():

    os_platform = utils.get_os()

    if os_platform == 'mac':
        cmd = ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=1']
    elif os_platform == 'linux':
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=1']
    elif os_platform == 'windows':
        cmd = ['powershell', 'Set-NetIPInterface', '-Forwarding', 'Enabled']

    assert subprocess.call(cmd) == 0


def disable_ip_forwarding():

    os_platform = utils.get_os()

    if os_platform == 'mac':
        cmd = ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=0']
    elif os_platform == 'linux':
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=0']
    elif os_platform == 'windows':
        cmd = ['powershell', 'Set-NetIPInterface', '-Forwarding', 'Disabled']

    assert subprocess.call(cmd) == 0
