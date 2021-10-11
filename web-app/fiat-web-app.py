## NOTE: web-app to receive commands from Fiat phone
## Author: Matteo Varvello (matteo.varvello@nokia.com)
## Date: 10/06/2021
## TEST 
## curl -H "Content-Type: application/json" --data '{"data":"testing data"}' http://localhost:8080/command

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

# simple function to read json from a POST message 
def read_json(req): 
	cl = req.headers['Content-Length']
	rawbody = req.body.read(int(cl))
	body = simplejson.loads(rawbody)
	return body 

# global parameters
port    = 8082                    # default listening port 
THREADS = []                      # list of threads 
ACL     = False                   # control whether application ACL rules should be used 
allowedips      = {               # ACL rules 
    '127.0.0.1':'-1',                     
}
session_id = ""
session_data = {}

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
        'server.socket_port': port, 
        'server.ssl_module':'builtin',
        'server.ssl_certificate':'certificate.pem',
    }
    cherrypy.config.update(server_config)

    # GET - ADD/REMOVE-ACL-RULE (localhost only)
    cherrypy.tree.mount(StringGeneratorWebService(), '/addACLRule', conf)
    cherrypy.tree.mount(StringGeneratorWebService(), '/removeACLRule', conf)
    
    # POST/REPORT-MEASUREMENTS 
    cherrypy.tree.mount(StringGeneratorWebService(), '/fiatData', conf)
 
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
	
		# parameters 
		ret_code = 202	   # default return code 
		result = []        # result to be returned when needed 
		ans = ''           # placeholder for response 

		# extract incoming IP address 
		src_ip = cherrypy.request.headers['Remote-Addr']

		# ACL control 
		if ACL: 
			if not src_ip in allowedips:
				cherrypy.response.status = 403
				print("Requesting ip address (%s) is not allowed" %(src_ip))
				return "Error: Forbidden" 

		# command to be executed
		if 'fiatData' in cherrypy.url():
			data = read_json(cherrypy.request)
			data = data['data'].split('\n')
			print(data)
			if len(data) > 2:
				print('ignore')
			else:
				data = data[0].split(',')
				ts = int(data[0])
				app = data[1]
				sensor = data[2]
				if sensor == 'GYR' or sensor == 'ACC':
					sensor_values = [float(d) for d in data[3:9]]
					print('ts: %d, app: %s, sensor: %s, values: %s' % (ts, app, sensor, str(sensor_values)))
				else:
					print('sensor is %s, ignore' % (sensor))

		# respond all good 
		cherrypy.response.headers['Content-Type'] = 'application/json'
		#cherrypy.response.headers['Content-Type'] = 'string'
		cherrypy.response.headers['Access-Control-Allow-Origin']  = '*'
		cherrypy.response.status = ret_code
		if ans == '':
			ans = 'OK\n'

		# all good, send response back 
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
	# start a thread which handle client-server communication 
	THREADS.append(Thread(target = th_web_app()))
	THREADS[-1].start()
	
	# listen to Ctrl+C
	signal.signal(signal.SIGINT, signal_handler)
