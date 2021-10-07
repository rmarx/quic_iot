import cherrypy
import random
import json
from cherrypy.lib.static import serve_file
import logging
import time
import numpy as np

import os
current_dir = os.path.dirname(os.path.abspath(__file__))

import sys
sys.path.append(os.getcwd() + '/..')

import joblib


VERIFY_VALID_DURATION = 10


# ------------------------------------- FIAT Handler ------------------------------------ #

def Amp(a, b, c):
    return [np.sqrt(a[i]*a[i] + b[i]*b[i] + c[i]*c[i]) for i in range(len(a))]

def preprocess_data(data):
    uac_x = [da['UAC'][0] for da in data]
    uac_y = [da['UAC'][1] for da in data]
    uac_z = [da['UAC'][2] for da in data]
    gyr_x = [da['GYR'][0] for da in data]
    gyr_y = [da['GYR'][1] for da in data]
    gyr_z = [da['GYR'][2] for da in data]

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
    return results

class FIATHandler:
    def __init__(self, mode, zksense_model='../zkSENSE/ML/decisiontree7.joblib'):
        self.data = []
        self.mode = mode
        self.clf = joblib.load(zksense_model)

        self.status = False # whether it is authenticated
        self.last_update_ts = time.time()

    def update_status():
        if time.time() - self.last_update_ts > VERIFY_VALID_DURATION:
            self.status = False

    def get_status():
        return self.status

    def new_data(self, data):
        # example data input:
        # MODE 0: 
        #   [0.1] * 48
        # MODE 1: 
        #   {
        #       'UAC': [0.1] * 6,
        #       'GYR': [0.1] * 6,
        #       'ts': 1633581551.092685,
        #   }
        print('FIATHandler.new_data', self.mode, len(data))
        self.data.append(data)
        if self.mode == 0:
            if len(self.data) >= 1:
                self.verify(self.data)
                self.data = []
        elif self.mode == 1:
            if len(self.data) >= 3:  # 250Hz * 0.3s
                self.data = preprocess_data(self.data)
                self.verify(self.data)
                self.data = []
        
    def verify(self, X):
        ret = self.clf.predict(X)
        print('FIATHandler.Verify!', ret, '\n\n')
        # TODO: check the meaning of the predict return
        if ret == False:
            self.status = True


# ------------------------------------- HTTP Handler ------------------------------------ #

CP_CONF = {
    '/': {
        'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
        'tools.sessions.on': True,
        'tools.response_headers.on': True,
        # 'tools.staticdir.on': True,
        # 'tools.staticdir.dir': os.path.abspath(os.getcwd())
    }
}

server_config={
    'server.socket_host': '0.0.0.0',
    'server.socket_port': 45679,
    # 'server.ssl_module':'builtin',
    # 'server.ssl_certificate':'certificate.pem',
}

def read_json(req): 
	cl = req.headers['Content-Length']
	rawbody = req.body.read(int(cl))
	body = json.loads(rawbody)
	#print(body)
	return body 


@cherrypy.expose
class FIATProxyService(object):
    def __init__(self, fiat_handler):
        self.fiat_handler = fiat_handler

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

        cherrypy.log("POST!!!")
        body = read_json(cherrypy.request)
        cherrypy.log(str(body))
        
        if len(body) > 0:
            self.fiat_handler.new_data(body)
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