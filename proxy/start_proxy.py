import os
import sys
sys.path.append(os.getcwd() + '/..')
import json
import time 

import joblib
import cherrypy
import random
import json
from cherrypy.lib.static import serve_file
import logging
from scapy.all import PcapReader


import utils 
from predictor import Predictor
from fiat_server import FIATHandler, FIATProxyService, CP_CONF, server_config


# ------------------------------------- FIAT Handler ------------------------------------ #

# mode:
# 0 -> pre-processing data at Android phone
# 1 -> receiving raw data from phone and processing mean and divation here
FIAT_MODE = 0
FIAT = FIATHandler(mode=FIAT_MODE)

# -------------------------------------- Predictor ------------------------------------- #

PREDICTOR = Predictor()

# --------------------------------------- Main() -------------------------------------- #


if __name__ == '__main__':
    cherrypy.config.update(server_config)
    cherrypy.quickstart(FIATProxyService(FIAT), '/', CP_CONF)

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


    pkt_count = 0
    while True:
        # pkt = get_new_packet()
        # pkt_count += 1

        # packet_type = PREDICTOR.new_pkt(pkt, pkt_count)
        # print('packet_type', packet_type)
        fiat_status = FIAT.get_status()
        print('fiat_status', fiat_status)

        # if packet_type == 2 and fiat_status is False:
        #     drop_packet()
        # else:
        #     forward_packet()