"""
Global shared state about the host.

"""
import sys

import threading
import time

import utils


CLIENT_VERSION = '1.0.3'


class HostState(object):

    def __init__(self, fiat_auth, predictor):

        self.host_ip = None
        self.host_mac = None
        self.gateway_ip = None
        self.packet_processor = None
        self.user_key = None
        self.secret_salt = None
        self.client_version = CLIENT_VERSION
        self.persistent_mode = True  # Always persistent to remove local Flask
        self.raspberry_pi_mode = False  # If true, app does not auto-quit upon UI inactivity

        # The following objects might be modified concurrently.
        self.lock = threading.Lock()
        #self.ip_mac_dict = {}  # IP -> MAC
        self.ip_mac_dict = {'192.168.5.1': 'b8:27:eb:8e:74:ef', '192.168.5.6': '18:69:d8:5b:be:7c', '192.168.5.14': '30:fd:38:7b:62:51', '192.168.5.15': '2c:aa:8e:15:da:5b', '192.168.5.19': '6a:6f:ad:75:45:d9'}
        self.pending_dhcp_dict = {}  # device_id -> hostname
        self.pending_resolver_dict = {}  # device_id -> resolver_ip
        self.pending_dns_dict = {}  # (device_id, domain) -> ip_set
        self.pending_flow_dict = {}  # flow_key -> flow_stats
        self.pending_ua_dict = {}  # device_id -> ua_set
        self.pending_tls_dict_list = []  # List of tls_dict
        self.pending_netdisco_dict = {}  # device_id -> device_info_list
        self.pending_syn_scan_dict = {}  # device_id -> port_list
        self.status_text = None
        #self.device_whitelist = ['s3df95f7a87', 'sb48959b20c', 's4dbce800d0', 's3425f51919', 's30dac03a76']
        self.device_whitelist = ['s3df95f7a87', 'sb48959b20c']
        #self.device_whitelist = []
        self.has_consent = False
        self.byte_count = 0
        self.is_inspecting_traffic = True
        self.fast_arp_scan = True  # Persists for first 5 mins
        self.last_ui_contact_ts = time.time()  # ts of /is_inspecting_traffic
        self.quit = False
        self.spoof_arp = True

        # FIAT
        self.fiat_auth = fiat_auth
        self.predictor = predictor

        # Constantly checks for IP changes on this host
        thread = threading.Thread(target=self.update_ip_thread)
        thread.daemon = True
        thread.start()

    def set_ip_mac_mapping(self, ip, mac):

        with self.lock:
            self.ip_mac_dict[ip] = mac

    def get_ip_mac_dict_copy(self):

        with self.lock:
            return dict(self.ip_mac_dict)

    def is_inspecting(self):

        with self.lock:
            return self.is_inspecting_traffic

    def update_ip_thread(self):

        prev_gateway_ip = None
        prev_host_ip = None

        while True:

            try:
                self.gateway_ip, _, self.host_ip = utils.get_default_route()
            except Exception:
                pass

            # Upon network changes, clear ARP cache.
            if self.gateway_ip != prev_gateway_ip or \
                    self.host_ip != prev_host_ip:

                with self.lock:
                    self.ip_mac_dict = {}
                    self.ip_mac_dict = {'192.168.5.1': 'b8:27:eb:8e:74:ef', '192.168.5.6': '18:69:d8:5b:be:7c', '192.168.5.14': '30:fd:38:7b:62:51', '192.168.5.15': '2c:aa:8e:15:da:5b', '192.168.5.19': '6a:6f:ad:75:45:d9'}

                prev_gateway_ip = self.gateway_ip
                prev_host_ip = self.host_ip

            time.sleep(15)
