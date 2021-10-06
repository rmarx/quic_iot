## NOTE: web-app to receive commands from phone
## Author: Matteo Varvello (varvello@brave.com)
## Date: 03/22/2019
## TEST 
## [go home]: curl -H "Content-Type: application/json" --data '{"command":"home_phone", "device":"ZY323LH272"}' http://localhost:8080/command
## [wake]: curl -H "Content-Type: application/json" --data '{"command":"wake_phone", "device":"ZY323LH272"}' http://localhost:8080/command

#!/usr/bin/python
#import random
import string
import json
import cherrypy
import os
from threading import Thread
import threading
import signal
import sys
import time 
import argparse
import simplejson
import subprocess

# currently unused import 
#import xmlrpclib
#try:
#    from urllib.parse import urlparse
#except ImportError:
#    from urlparse import urlparse
#from geoip import geolite2
#import socket
#import requests 

# simple function to read json from a POST message 
def read_json(req): 
	cl = req.headers['Content-Length']
	rawbody = req.body.read(int(cl))
	body = simplejson.loads(rawbody)
	return body 

# global parameters
device_id = ''                    # device currently being mirrored 
screen_width  = ''                # width of device screen 
screen_height = ''	              # height of device screen 
last_command_time = 0             # time of the last command
port    = 8080                    # default listening port 
THREADS = []                      # list of threads 
ACL     = False                   # control whether application ACL rules should be used 
allowedips      = {               # ACL rules 
    '127.0.0.1':'-1',                     
}
exp_ips = ['129.31.146.132', '72.68.28.11', "98.109.116.110"]  # IP allowed with experimenter role
supported_commands = ['start_monsoon',                         # supported commands
			'stop_monsoon', 'back_phone',  
			'home_phone', 'wake_phone', 
			'switch_phone', 
			'connection_status', 
			'safe_switch',
			'close_all']
list_disallowed_buttons = [ 'Power ( )',     # not to press buttons (not used here. Just an exomaple from Kodi)
                          'Settings ( )', 
                          'Settings (*)']
user_test = False                 # keep track if a user test is running or not 
assignmentId = ""                 # assignment identifier 
session_id = ""
session_data = {}

# update crowdsourced automation
def update_crowd_res(command):
	out_file = "./crowdsourcing-results/" + session_id + "/" + assignmentId + ".adb"
	with open(out_file, "a") as myfile:
	    myfile.write(command + '\n')
	
# function to see which screen/device is being mirrored
def  find_phone():
	global device_id

	command = "ps aux | grep adb | grep scrcpy"
	#pl = subprocess.Popen(command.split(' '), stdout=subprocess.PIPE).communicate()[0]	
	pl = subprocess.Popen(['ps', '-a', '-u', '-x'], stdout=subprocess.PIPE).communicate()[0]
	for line in pl.decode('utf-8').split('\n'):
		if 'scrcpy' in line and 'adb' not in line:
			fields = line.split(' ')
			i = 0
			for i in range(len(fields)):
				if fields[i] == '-s':
					device_id = fields[i+1]
					break 
				i += 1
			break 
	print("Current device in scrcpy: ", device_id)



# function to check if monsoon is already running
def  check_monitor_status():
	#command = "ps -a | grep collect-power-measurements.py | grep -v grep | wc -l"
	#ans = run_bash(command)
	pl = subprocess.Popen(['ps', '-a', '-u', '-x'], stdout=subprocess.PIPE).communicate()[0]
	for line in pl.decode('utf-8').split('\n'):
		if 'collect-power-measurements.py' in line:
			print("Monsoon collection is already running.")
			return True 
	print("No previous monsoon collection running.")
	return False 

# function to get pin status for a given device
def  get_GPIO_pin_status(device_id):
	# filter port if an IP is used #FIXME 
	if '5555' in device_id: 
		device_id = device_id.split(':')[0]

	# find current pin for device 
	phone_file = '../automation/phones-info.txt'
	if os.path.isfile(phone_file):
		lines = []
		with open(phone_file) as f:
			lines = f.readlines()
		for line in lines: 
			if device_id in line: 
				#print line.strip().split('\t')
				current_pin = line.strip().split('\t')[-2]
				phone_name = line.strip().split('\t')[0]
				print("Name: " + phone_name + " Device: " + device_id +  " GPIO-pin: " +  current_pin)
				break

	# read pin status
	command = "gpio read " + current_pin
	pin_status = int(run_bash(command))

	# all good 
	return pin_status, phone_name
				
# function to run a bash command
def run_bash(bashCommand, verbose = True):
	process = subprocess.Popen(bashCommand.split(), stdout = subprocess.PIPE, stdin =subprocess.PIPE, shell = False)
	output, error = process.communicate()
	
	#if verbose: 
	print("Command: " + bashCommand + " Output: " + str(output) + " Error: " + str(error))

	# all good (add a check?)
	return str(output.decode('utf-8'))

# FIXME -- can this go? 
def CORS():
	cherrypy.response.headers["Access-Control-Allow-Origin"] = "*"

def cors():
  # logging 
  if cherrypy.request.method == 'OPTIONS':
    # logging 
    #print "received a pre-flight request"
    # preflign request 
    # see http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0
    cherrypy.response.headers['Access-Control-Allow-Methods'] = 'POST'
    cherrypy.response.headers['Access-Control-Allow-Headers'] = 'content-type'
    cherrypy.response.headers['Access-Control-Allow-Origin']  = '*'
    # tell CherryPy no avoid normal handler
    return True
  else:
    cherrypy.response.headers['Access-Control-Allow-Origin'] = '*'


# thread to control client-server communication
def th_web_app():
    # configuration 
    conf = {
        '/': {
            'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
            'tools.sessions.on': True,
            'tools.response_headers.on': True,
        }
    }

    cherrypy.tools.cors = cherrypy._cptools.HandlerTool(cors)
    server_config={
        'server.socket_host': '0.0.0.0',
        'server.socket_port': port, #8080
        'server.ssl_module':'builtin',
        'server.ssl_certificate':'certificate.pem',
    }
    cherrypy.config.update(server_config)

    # start serving requests 
    #cherrypy.config.update({'server.socket_host': '0.0.0.0' })
    #cherrypy.config.update({'server.socket_port': port,})
    
    # GET - ADD/REMOVE-ACL-RULE (localhost only)
    cherrypy.tree.mount(StringGeneratorWebService(), '/addACLRule', conf)
    cherrypy.tree.mount(StringGeneratorWebService(), '/removeACLRule', conf)
    
    # POST/REPORT-MEASUREMENTS 
    cherrypy.tree.mount(StringGeneratorWebService(), '/command', conf)
    cherrypy.tree.mount(StringGeneratorWebService(), '/coordinates', conf)
    cherrypy.tree.mount(StringGeneratorWebService(), '/videoconfData', conf)
    cherrypy.tree.mount(StringGeneratorWebService(), '/fiatData', conf)
 
    # CROWDSOURCING APPLICATION
    cherrypy.tree.mount(StringGeneratorWebService(), '/browser-automation', conf)
    cherrypy.tree.mount(StringGeneratorWebService(), '/start-test', conf)
    cherrypy.tree.mount(StringGeneratorWebService(), '/stop-test', conf)
    cherrypy.tree.mount(StringGeneratorWebService(), '/replay', conf)
    cherrypy.tree.mount(StringGeneratorWebService(), '/ban', conf)
    cherrypy.tree.mount(StringGeneratorWebService(), '/ratings', conf)
 
    # start cherrypy engine 
    cherrypy.engine.start()
    cherrypy.engine.block()

# catch ctrl-c
def signal_handler(signal, frame):

	# logging 
	print('You pressed Ctrl+C!')

	# kill throughput thread 
	print("stopping main thread")
	THREADS[0].do_run = False
	THREADS[0].join()
	
	# kill cherrypy
	print("stopping cherrypy webapp")
	cherrypy.engine.exit()

	# exiting from main process
	sys.exit(0)


# function to read phones info via json
def get_device_info(json_file):
	global screen_width, screen_height

	with open(json_file) as json_file:
		data = json.load(json_file)
	for device in data: 
		if device['adb_identifier'] == device_id or (device['ip'] + ':5555') == device_id:
			screen_res = device ['screen_res']
			screen_width = float(screen_res.split('x')[0])
			screen_height = float(screen_res.split('x')[1])
			print("Found %s for device %s" %(screen_res, device_id))
			return screen_res
	# error 
	print("Device not found")
	sys.exit(-1)


# function to translate browser coordinates into device coords
def translate_coordinates(X, Y):

	##################TMP###################
	#xScrpy = 320 # old value, see how to make dynamic
	xScrpy = 360
	yScrpy = 640
	xVNC   = 500
	yVNC   = 800
	######################################

	# translation
	xPadding = (xVNC - xScrpy)/2
	yPadding = (yVNC - yScrpy)/2
	xRatio   = screen_width/xScrpy
	yRatio   = screen_height/yScrpy
	xVal     = int(xRatio*(X - xPadding))
	yVal     = int(yRatio*(Y - yPadding))

	# all good 
	return xVal, yVal

# generate adb scroll up/down command - FIXME: temporary hard coded for LG phone
def scroll(direction, sleep_time, X, Y):
	sleep_command = "sleep " +  str(sleep_time)
	
	# verify mouse event is inside the device and compute action
	x_coord, y_coord = translate_coordinates(X, Y)
	print(x_coord, y_coord, screen_width, screen_height)	
	command = ""
	if x_coord > 0 and x_coord < screen_width and y_coord > 0 and y_coord < screen_height:
		x_coord = screen_width/2
		if direction == "down":
			y_start = 700
			y_end = 570
			if device_id == "5200eb945bbb25e7":
				y_end = 595 
		elif direction == "up":
			y_start = 570
			if device_id == "5200eb945bbb25e7":
				y_start = 595 
			y_end = 700
		command = " && adb -s " + device_id + " shell input swipe " + str(x_coord) + " " + str(y_start) + " " + str(x_coord) + " " + str(y_end)

	# all good 
	return sleep_command + command

# generate touch event via adb
def touch_event(X, Y, sleep_time):
	# compute how long to wait 
	sleep_command = "sleep " +  str(sleep_time)
	x_coord, y_coord = translate_coordinates(X, Y)
	print(x_coord, y_coord, screen_width, screen_height)	

	# verify touch event is inside the device 
	command = ""
	if x_coord > 0 and x_coord < screen_width and y_coord > 0 and y_coord < screen_height:
		command = " && adb -s " + device_id + " shell \"input tap " + str(x_coord) + " " + str(y_coord) + "\""

	# all good 
	return sleep_command + command 

# generate keyboard input via adb 
def key_event(key, sleep_time):
	sleep_command = "sleep " + str(sleep_time)
	command = ""
	if "Key" in key: 
		key = key.replace("Key", "").lower()
		command = "adb -s " + device_id + " shell input text " + key
	elif "Period" in key: 
		command = "adb -s " + device_id + " shell input text ." 
	elif key == "Enter": 
		command = "adb -s " + device_id + " shell input keyevent 66"
	return sleep_command + " && " + command 

@cherrypy.expose
class StringGeneratorWebService(object):

	@cherrypy.tools.accept(media='text/plain')
	def GET(self, var=None, **params):
		
		# log last IP that contacted the server
		src_ip = cherrypy.request.headers['Remote-Addr']
		
		# ACL control 
		if ACL: 
			if not src_ip in allowedips:
				cherrypy.response.status = 403
				print("Requesting ip address (%s) is not allowed" %(src_ip))
				return "Error: Forbidden" 

		# add ACL rule
		if 'addACLRule' in cherrypy.url():
			if 'ip' in cherrypy.request.params: 
				ip_to_add = cherrypy.request.params['ip']
				currentTime = int(time.time()) * 1000
				if ip_to_add in allowedips:
					print("Updating ip %s in allowedips" %(ip_to_add))
					msg = "Rule correctly updated"
				else:
					print("Adding new ip %s to allowedips" %(ip_to_add))
					msg = "Rule correctly added"

				# update or add the rule 
				allowedips[ip_to_add] = currentTime
				
				# respond all good 
				cherrypy.response.status = 200
				return msg

		# remove ACL rule 
		elif 'removeACLRule' in cherrypy.url():
			if 'ip' in cherrypy.request.params: 
				ip_to_remove = cherrypy.request.params['ip']
				if ip_to_remove in allowedips:
					del allowedips[ip_to_remove] 
					print("Remove ip %s from allowedips" %(ip_to_remove))
					
					# respond all good 
					cherrypy.response.status = 200
					return "Rule correctly removed"
				else:
					# respond nothing was done 
					cherrypy.response.status = 202
					return "Rule could not be removed since not existing"
		
	# handle POST requests 
	def POST(self, name="test"):
		print("Received a POST")
		# parameters 
		ret_code = 202	   # default return code 
		result = []        # result to be returned when needed 
		ans = ''           # placeholder for response 
		global last_command_time
		global user_test 
		global assignmentId
		global sesion_data 

		# extract incoming IP address 
		src_ip = cherrypy.request.headers['Remote-Addr']

		# ACL control 
		if ACL: 
			if not src_ip in allowedips:
				cherrypy.response.status = 403
				print("Requesting ip address (%s) is not allowed" %(src_ip))
				return "Error: Forbidden" 

		# command to be executed
		if 'videoconfData' in cherrypy.url():
			img_data = read_json(cherrypy.request).replace("data:image/jpeg;base64,","")
			print("Saving image to file")
			with open("image.jpg", "wb") as fh:
			    fh.write(img_data.decode('base64'))

		# command to be executed
		if 'fiatData' in cherrypy.url():
			print(read_json(cherrypy.request))
		if 'coordinates' in cherrypy.url():
			supported = True
			if last_command_time != 0: 
				sleep_time = time.time() - last_command_time
			else: 
				sleep_time = 0
			last_command_time = time.time()

			# read JSON data posted 
			body = read_json(cherrypy.request)
			action = body['action']
			adb_action = ""
			if action == 'wheel': 
				# for now assuming just scrolling up and down
				deltaY = body['deltaY']
				if deltaY > 0: 
					adb_action = scroll("down", sleep_time, body['X'], body['Y'])
				if deltaY < 0: 
					adb_action = scroll("up", sleep_time, body['X'], body['Y'])
			elif action == 'touch': 
				x_coord = body['X']
				y_coord = body['Y']
				adb_action = touch_event(x_coord, y_coord, sleep_time)
			elif action == 'key': 
				key = body['code']
				adb_action = key_event(key, sleep_time)
			else: 
				supported = False 
				print("action not supported yet")

			# keep log of action
			if supported: 
				print(adb_action, user_test)
				if user_test:
					update_crowd_res(adb_action)
		
		# install/launch/automate  browser from playstore 
		elif 'browser-automation' in cherrypy.url():
			data = read_json(cherrypy.request)
			command  = data['command']
			browser  = data['browser']
			test_id  = data['testID']
			actionId = data['action']
			print("Command: %s Browser: %s Test-ID: %s Action-ID: %s" %(command, browser, test_id, actionId))
			if command == "start-automation": 
				assignmentId = test_id
				session_data[assignmentId] = (time.time(), actionId, browser)
				user_test = True 
			elif command == "stop-automation":
				user_test = False 				
			command = "../human-automation/automate.sh " + command + ' ' + test_id + ' ' + device_id  + ' ' + browser + ' ' + session_id + ' ' + actionId
			run_bash(command)
		
		# user test start 
		elif 'start-test' in cherrypy.url():
			user_test = True 
			assignmentId = read_json(cherrypy.request)
			last_command_time = time.time()
			command = "../automation/usability-test.sh start " + assignmentId + ' ' + device_id + ' ' + session_id + ' ' + actionId
			run_bash(command)
		
		# user test end
		elif 'stop-test' in cherrypy.url():
			sleep_time = time.time() - last_command_time
			update_crowd_res("sleep " + str(sleep_time))
			#last_command_time = 0 
			last_command_time = time.time()    #MV -- WARNING: this is needed for the workload 
			user_test = False 
			assignmentId = read_json(cherrypy.request)
			command = "../automation/usability-test.sh stop " + assignmentId + ' ' + device_id + ' ' + session_id + ' ' + actionId
			run_bash(command)
	
		# user test end
		elif 'replay' in cherrypy.url():
			assignmentId = read_json(cherrypy.request)
			command = "../automation/usability-test.sh replay " + assignmentId + ' ' + device_id + ' ' + actionId
			run_bash(command)
		
		# user test end
		elif 'ban' in cherrypy.url():
			assignmentId = read_json(cherrypy.request)
			print('ban ' + assignmentId)
			command = "../automation/usability-test.sh stop " + assignmentId + ' ' + device_id
			run_bash(command)
	
		# user test end
		elif 'ratings' in cherrypy.url():
			data = read_json(cherrypy.request)
			### FIXME -- ratings need to be stored somewhere
			print(data)
			## FIXME: need to clean session data eventually
			#curr_data = session_data[assignmentId] 
			#browser = curr_data[2]
			#actionId = curr_data[1]
			#print(browser, actionId)
			### TODO: -- keep track of ratings automation > X using browser/action/testId-rating
			### TODO: -- update browser config file with available automations 
		
		# command to be executed
		elif 'command' in cherrypy.url():
			# read JSON data posted 
			body = read_json(cherrypy.request)
	
			# check for error 
			print("JSON received: " + str(body))
			if 'command' not in body:
				ans = "ERROR: missing either command or device key in json data rx\n" 
			else:		
				# extract command and device identifier
				rx_command = body['command'].split(':')[0]
					
				# see if device id needs to be overwritten for some weird reason
				#if 'device' in body: 
				#	device_id = body['device'].split(':')[0]
				
				# switch on supported commands
				if rx_command not in supported_commands: 
					print("ERROR: Command %s not supported yet!" %(body['command']))
					ans = "ERROR: Command " + str(body['command']) + " not supported yet!\n"
					ret_code = 404
				else:
					# Check for IP privilege for the experiment 
					#if src_ip != experimenter_ip and (rx_command == 'start_monsoon' or rx_command == 'safe_switch'):
					if src_ip not in exp_ips and (rx_command == 'start_monsoon' or rx_command == 'safe_switch'):
						print("Requesting ip address (%s) does not have experiment role"  %(src_ip))
						return "Error: Forbidden"

					# switch between commands 
					if rx_command == 'start_monsoon':
						# check that monsoon is not running already 
						is_running = check_monitor_status()
						if is_running: 
							ans = 'Monsoon is already running. Please wait 30 secs'
						else: 
							# get pin status for mirrored device 
							pin_status, phone_name  = get_GPIO_pin_status(device_id)

							# start power measurement if device is connected to monsoon
							if pin_status == 0: 
								command = "sudo python3 -u ../monsoon/collect-power-measurements.py 30 power-log-web.csv"
								run_bash(command)
								ans = 'Monsoon running for 30 secs'
							else: 
								ans = 'ERROR - please activate monsoon first'
					## MV -- u cannot really stop it ... 
					#elif rx_command == 'stop_monsoon':
					#	command = "XXXX"
					elif rx_command == 'back_phone':
						command = "adb -s " + device_id + " shell input keyevent KEYCODE_BACK"
						run_bash(command)
					elif rx_command == 'home_phone':
						command = "adb -s " + device_id + " shell input keyevent KEYCODE_HOME"
						run_bash(command)
					elif rx_command == 'wake_phone':
						command = "adb -s " + device_id + " shell input keyevent 26"
						run_bash(command)
					elif rx_command == 'switch_phone':
						command = "./switch-phone.sh"
						run_bash(command)
					elif rx_command == 'close_all':
						command = "./close-all.sh" + ' ' + device_id
						run_bash(command)
					elif rx_command == 'connection_status':
						# get pin status for mirrored device 
						#pin_status, phone_name  = get_GPIO_pin_status(device_id)
						pin_status = 1 
						phone_name = "FIXME"
						print(pin_status, phone_name)
	
						# prepare message to be returned 
						if pin_status == 1: 
							ans += 'battery\n'
						elif pin_status == 0: 
							ans += 'monsoon\n'
						else: 
							ans = 'error - GPIO pin or device was not found\n'
							ret_code = 404
					elif rx_command == 'safe_switch':
						# detect which switch is needed (mon-to-batt or batt-to-mon)
						pin_status, phone_name  = get_GPIO_pin_status(device_id)
						if pin_status == 1: 
							command = "../automation/safe-switch.sh -d " + phone_name + " -o batt-to-mon"
						elif pin_status == 0: 
							command = "../automation/safe-switch.sh -d " + phone_name + " -o mon-to-batt"
						#print(command)
						run_bash(command)
						ans += 'REFRESH'

		# respond all good 
		#cherrypy.response.headers['Content-Type'] = 'application/json'
		cherrypy.response.headers['Content-Type'] = 'string'
		cherrypy.response.headers['Access-Control-Allow-Origin']  = '*'
		cherrypy.response.status = ret_code
		if ans == '':
			ans = 'OK\n'

		# all good, send response back 
		#return ans
		return ans.encode('utf8')

	def OPTIONS(self, name="test"): 
		# preflign request 
		# see http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0
		cherrypy.response.headers['Access-Control-Allow-Methods'] = 'POST'
		cherrypy.response.headers['Access-Control-Allow-Headers'] = 'content-type'
		cherrypy.response.headers['Access-Control-Allow-Origin']  = '*'

	def PUT(self, another_string):
		cherrypy.session['mystring'] = another_string

	def DELETE(self):
		cherrypy.session.pop('mystring', None)

# main goes here 
if __name__ == '__main__':
	# read input 
	session_id = sys.argv[1] 
	if(len(sys.argv) > 2): 
		port = int(sys.argv[2])
		print("Changed running port to: ", port)

	# start a thread which handle client-server communication 
	THREADS.append(Thread(target = th_web_app()))
	THREADS[-1].start()
	
	# listen to Ctrl+C
	signal.signal(signal.SIGINT, signal_handler)
