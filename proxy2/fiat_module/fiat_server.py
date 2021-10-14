import cherrypy
import random
import json
from cherrypy.lib.static import serve_file
import logging
import time
import numpy as np
import simplejson

import os
current_dir = os.path.dirname(os.path.abspath(__file__))
import sys

import joblib


VERIFY_VALID_DURATION = 10


# ------------------------------------- FIAT Handler ------------------------------------ #

def Amp(a, b, c):
    return [np.sqrt(a[i]*a[i] + b[i]*b[i] + c[i]*c[i]) for i in range(len(a))]

def preprocess_data(data):
    uac_x = [da[0] for da in data['UAC']]
    uac_y = [da[1] for da in data['UAC']]
    uac_z = [da[2] for da in data['UAC']]
    gyr_x = [da[0] for da in data['GYR']]
    gyr_y = [da[1] for da in data['GYR']]
    gyr_z = [da[2] for da in data['GYR']]

    # TODO: modify this to real features
    results = [
        min(uac_x),
        min(uac_x),
        min(uac_x),
        min(Amp(uac_x, uac_x, uac_x)),
        max(uac_x),
        max(uac_x),
        max(uac_x),
        max(Amp(uac_x, uac_x, uac_x)),
        np.ptp(uac_x),
        np.ptp(uac_x),
        np.ptp(uac_x),
        np.ptp(Amp(uac_x, uac_x, uac_x)),
        np.std(uac_x),
        np.std(uac_x),
        np.std(uac_x),
        np.mean(Amp(uac_x, uac_x, uac_x)),
        np.mean(uac_x),
        np.mean(uac_x),
        np.mean(uac_x),
        np.mean(Amp(uac_x, uac_x, uac_x)),
        np.mean(uac_x),
        np.mean(uac_x),
        np.mean(uac_x),
        np.mean(Amp(uac_x, uac_x, uac_x)),

        min(gyr_x),
        min(gyr_x),
        min(gyr_x),
        min(Amp(gyr_x, gyr_x, gyr_x)),
        max(gyr_x),
        max(gyr_x),
        max(gyr_x),
        max(Amp(gyr_x, gyr_x, gyr_x)),
        np.ptp(gyr_x),
        np.ptp(gyr_x),
        np.ptp(gyr_x),
        np.ptp(Amp(gyr_x, gyr_x, gyr_x)),
        np.std(gyr_x),
        np.std(gyr_x),
        np.std(gyr_x),
        np.mean(Amp(gyr_x, gyr_x, gyr_x)),
        np.mean(gyr_x),
        np.mean(gyr_x),
        np.mean(gyr_x),
        np.mean(Amp(gyr_x, gyr_x, gyr_x)),
        np.mean(gyr_x),
        np.mean(gyr_x),
        np.mean(gyr_x),
        np.mean(Amp(gyr_x, gyr_x, gyr_x)),
    ]
    return [results]

class FIATHandler:
    def __init__(self, mode, zksense_model='../../zkSENSE/ML/decisiontree7.joblib'):
        self.data = []
        self.mode = mode
        if self.mode == 1:
            self.data = {
                'UAC': [],
                'GYR': [],
                'ts': 0
            }
        self.clf = joblib.load(zksense_model)

        self.status = False # whether it is authenticated
        self.last_update_ts = time.time()

    def update_status(self):
        if time.time() - self.last_update_ts > VERIFY_VALID_DURATION:
            self.status = False

    def get_status(self):
        self.update_status()
        return self.status

    def new_data(self, new_data):
        # example data input:
        # MODE 0: 
        #   [0.1] * 48
        # MODE 1: 
        #   {
        #       'UAC': [0.1] * 6,
        #       'GYR': [0.1] * 6,
        #       'ts': 1633581551.092685,
        #   }
        print('FIATHandler.new_data', self.mode, len(new_data))
        if self.mode == 0:
            self.data.append(new_data)
            self.verify(self.new_data)
            self.data = []
        elif self.mode == 1:
            self.data[new_data['sensor']].append(new_data['sensor_values'])
            if self.data['ts'] == 0:
                self.data['ts'] = new_data['ts']
            #print('data000', self.data)
            if (len(self.data['UAC']) >= 2
                and len(self.data['GYR']) >= 2
                and (new_data['ts'] - self.data['ts'] > 0.1)): 
                #print('data111', self.data)
                self.data = preprocess_data(self.data)
                #print('data222', self.data)
                self.verify(self.data)
                self.data = {
                    'UAC': [],
                    'GYR': [],
                    'ts': 0
                }
        
    def verify(self, X):
        print('X', X)
        #return
        ret = self.clf.predict(X)[0]
        print('FIATHandler.Verify!', ret, '\n\n')
        # TODO: check the meaning of the predict return
        if ret == 0:
            self.status = True
            self.last_update_ts = time.time()


# ------------------------------------- HTTP Handler ------------------------------------ #

CP_CONF = {
    '/': {
        'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
        'tools.sessions.on': True,
        'tools.response_headers.on': True,
        # 'tools.staticdir.on': True,
        # 'tools.staticdir.dir': os.path.abspath(os.getcwd())
    },
    '/fiatData': {
        'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
        'tools.sessions.on': True,
        'tools.response_headers.on': True,
    }
}

server_config={
    'server.socket_host': '0.0.0.0',
    'server.socket_port': 8083,
    'server.ssl_module':'builtin',
    'server.ssl_certificate':'../web-app/certificate.pem',
}

def read_json(req): 
	cl = req.headers['Content-Length']
	rawbody = req.body.read(int(cl))
	#print('rawbody', rawbody)
	body = simplejson.loads(rawbody)
	#print(body)
	return body 


@cherrypy.expose
class FIATProxyService(object):
    def __init__(self, fiat_handler):
        self.fiat_handler = fiat_handler
        print('Proxy iniated')

    #@cherrypy.tools.accept(media='text/plain')
    def GET(self, var=None, **params):
        pass
        # cherrypy.log("GET!!!")
        # cherrypy.log(str(var), str(params))
        # url_splits = cherrypy.url().split('/')
        # page = url_splits[-1]
        # return serve_file(os.path.join(current_dir, "dvpn.html"), content_type='text/html')

        # cherrypy.response.status = 404
        # return "ERROR"
        
    def POST(self, var=None, **params):
        ret_code = 200
        result = []
        ans = ''

        #cherrypy.log("POST!!!")
        if 'fiatData' in cherrypy.url():
            data = read_json(cherrypy.request)
            #print(data)
            data = data['data'].split('\n')
            if len(data) > 2:
                print('ignore non-app data')
            else:
                data = data[0].split(',')
                ts = int(data[0])
                app = data[1]
                sensor = data[2]
                if sensor == 'GYR' or sensor == 'UAC':
                    sensor_values = [float(d) for d in data[3:9]]
                    new_data = {
                        'ts': ts,
                        'app': app,
                         'sensor': sensor,
                        'sensor_values': sensor_values
                    }
                    self.fiat_handler.new_data(new_data)
                    #print('ts: %d, app: %s, sensor: %s, values: %s' % (ts, app, sensor, str(sensor_values)))
                else:
                    print('sensor is %s, ignore' % (sensor))
                    
        if self.fiat_handler.status == True:
            ans = 'OK\n'
            cherrypy.response.status = 200
        else:
            ans = 'Failed\n'
            cherrypy.response.status = 404
        return ans.encode('utf8')

        # url_splits = cherrypy.url().split('/')
        # print(url_splits)
        # if (url_splits[-1] == "index"):
        #     self.controller.update_access(web2controller(body))
        # else:
        #     cherrypy.response.status = 404
        #     return "ERROR"


    def PUT(self, another_string):
        return 'PUT'

    def DELETE(self):
        return 'DELETE'
