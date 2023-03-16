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

import pandas as pd
import joblib


VERIFY_VALID_DURATION = 10
BEFORE_PORTION = 3


# ------------------------------------- FIAT Handler ------------------------------------ #

def Amp(a, b, c):
    return [np.sqrt(a[i]*a[i] + b[i]*b[i] + c[i]*c[i]) for i in range(len(a))]

def preprocess_data(data, mapper):
    uac_before_index = int(len(data['UAC']) / BEFORE_PORTION)
    gyr_before_index = int(len(data['GYR']) / BEFORE_PORTION)

    uac1_x = [da[3] for da in data['UAC'][:uac_before_index]]
    uac1_y = [da[4] for da in data['UAC'][:uac_before_index]]
    uac1_z = [da[5] for da in data['UAC'][:uac_before_index]]
    uac2_x = [da[3] for da in data['UAC'][uac_before_index:]]
    uac2_y = [da[4] for da in data['UAC'][uac_before_index:]]
    uac2_z = [da[5] for da in data['UAC'][uac_before_index:]]

    uac1_dev_x = [aa - bb for aa, bb in zip(uac1_x[1:], uac1_x[:-1])]
    uac1_dev_y = [aa - bb for aa, bb in zip(uac1_y[1:], uac1_y[:-1])]
    uac1_dev_z = [aa - bb for aa, bb in zip(uac1_z[1:], uac1_z[:-1])]
    uac2_dev_x = [aa - bb for aa, bb in zip(uac2_x[1:], uac2_x[:-1])]
    uac2_dev_y = [aa - bb for aa, bb in zip(uac2_y[1:], uac2_y[:-1])]
    uac2_dev_z = [aa - bb for aa, bb in zip(uac2_z[1:], uac2_z[:-1])]

    gyr1_x = [da[3] for da in data['GYR'][:gyr_before_index]]
    gyr1_y = [da[4] for da in data['GYR'][:gyr_before_index]]
    gyr1_z = [da[5] for da in data['GYR'][:gyr_before_index]]
    gyr2_x = [da[3] for da in data['GYR'][gyr_before_index:]]
    gyr2_y = [da[4] for da in data['GYR'][gyr_before_index:]]
    gyr2_z = [da[5] for da in data['GYR'][gyr_before_index:]]

    gyr1_dev_x = [aa - bb for aa, bb in zip(gyr1_x[1:], gyr1_x[:-1])]
    gyr1_dev_y = [aa - bb for aa, bb in zip(gyr1_y[1:], gyr1_y[:-1])]
    gyr1_dev_z = [aa - bb for aa, bb in zip(gyr1_z[1:], gyr1_z[:-1])]
    gyr2_dev_x = [aa - bb for aa, bb in zip(gyr2_x[1:], gyr2_x[:-1])]
    gyr2_dev_y = [aa - bb for aa, bb in zip(gyr2_y[1:], gyr2_y[:-1])]
    gyr2_dev_z = [aa - bb for aa, bb in zip(gyr2_z[1:], gyr2_z[:-1])]

    df = pd.DataFrame({
        'uac_mean1_x': [np.mean(uac1_x)],
        'uac_mean1_y': [np.mean(uac1_y)],
        'uac_mean1_z': [np.mean(uac1_z)],
        'uac_mean2_x': [np.mean(uac2_x)],
        'uac_mean2_y': [np.mean(uac2_y)],
        'uac_mean2_z': [np.mean(uac2_z)],
        'uac_std1_x': [np.std(uac1_x)],
        'uac_std1_y': [np.std(uac1_y)],
        'uac_std1_z': [np.std(uac1_z)],
        'uac_std2_x': [np.std(uac2_x)],
        'uac_std2_y': [np.std(uac2_y)],
        'uac_std2_z': [np.std(uac2_z)],
        'uac_dev_mean1_x': [np.mean(uac1_dev_x)],
        'uac_dev_mean1_y': [np.mean(uac1_dev_y)],
        'uac_dev_mean1_z': [np.mean(uac1_dev_z)],
        'uac_dev_mean2_x': [np.mean(uac2_dev_x)],
        'uac_dev_mean2_y': [np.mean(uac2_dev_y)],
        'uac_dev_mean2_z': [np.mean(uac2_dev_z)],
        'uac_dev_std1_x': [np.std(uac1_dev_x)],
        'uac_dev_std1_y': [np.std(uac1_dev_y)],
        'uac_dev_std1_z': [np.std(uac1_dev_z)],
        'uac_dev_std2_x': [np.std(uac2_dev_x)],
        'uac_dev_std2_y': [np.std(uac2_dev_y)],
        'uac_dev_std2_z': [np.std(uac2_dev_z)],
        'gyr_mean1_x': [np.mean(gyr1_x)],
        'gyr_mean1_y': [np.mean(gyr1_y)],
        'gyr_mean1_z': [np.mean(gyr1_z)],
        'gyr_mean2_x': [np.mean(gyr2_x)],
        'gyr_mean2_y': [np.mean(gyr2_y)],
        'gyr_mean2_z': [np.mean(gyr2_z)],
        'gyr_std1_x': [np.std(gyr1_x)],
        'gyr_std1_y': [np.std(gyr1_y)],
        'gyr_std1_z': [np.std(gyr1_z)],
        'gyr_std2_x': [np.std(gyr2_x)],
        'gyr_std2_y': [np.std(gyr2_y)],
        'gyr_std2_z': [np.std(gyr2_z)],
        'gyr_dev_mean1_x': [np.mean(gyr1_dev_x)],
        'gyr_dev_mean1_y': [np.mean(gyr1_dev_y)],
        'gyr_dev_mean1_z': [np.mean(gyr1_dev_z)],
        'gyr_dev_mean2_x': [np.mean(gyr2_dev_x)],
        'gyr_dev_mean2_y': [np.mean(gyr2_dev_y)],
        'gyr_dev_mean2_z': [np.mean(gyr2_dev_z)],
        'gyr_dev_std1_x': [np.std(gyr1_dev_x)],
        'gyr_dev_std1_y': [np.std(gyr1_dev_y)],
        'gyr_dev_std1_z': [np.std(gyr1_dev_z)],
        'gyr_dev_std2_x': [np.std(gyr2_dev_x)],
        'gyr_dev_std2_y': [np.std(gyr2_dev_y)],
        'gyr_dev_std2_z': [np.std(gyr2_dev_z)],
    })
    processed_data = mapper.transform(df)
    return processed_data

class FIATHandler:
    def __init__(self, mode, zksense_model='models/zksense_decisiontree9.joblib', scalar='models/zksense_scalar.joblib'):
        self.data = []
        self.mode = mode
        if self.mode == 1:
            self.data = {
                'UAC': [],
                'GYR': [],
                'ts': []
            }
        self.clf = joblib.load(zksense_model)
        self.scalar = joblib.load(scalar)

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
        if self.mode == 0:
            print('FIATHandler.new_data0', self.mode, len(new_data))
            self.data.append(new_data)
            self.verify(self.new_data)
            self.data = []

        elif self.mode == 1:
            # print('FIATHandler.new_data1', self.mode, len(new_data))
            self.data[new_data['sensor']].append(new_data['sensor_values'])
            self.data['ts'].append(new_data['ts'])
            # print('self.data', self.data)
            # if len(self.data['ts']) > 0:
                # print('FIATHandler.new_data2', len(self.data['UAC']), len(self.data['GYR']), self.data['ts'][-1] - self.data['ts'][0])

            if (len(self.data['UAC']) >= 2*BEFORE_PORTION
                and len(self.data['GYR']) >= 2*BEFORE_PORTION
                and (self.data['ts'][-1] - self.data['ts'][0] > 0.3)): 
                # print('verify', len(self.data['UAC']), len(self.data['GYR']), self.data['ts'][-1] - self.data['ts'][0])
                processed_data = preprocess_data(self.data, self.scalar)
                self.verify(processed_data)
                self.data = {
                    'UAC': [],
                    'GYR': [],
                    'ts': []
                }
        
    def verify(self, X):
        # print('X', X)
        #return
        ret = self.clf.predict(X)[0]
        print('FIATHandler.Verify!', ret)#, '\n\n')
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


if __name__ == "__main__":
    fiat_handler = FIATHandler(mode=1, zksense_model='models/zksense_decisiontree9.joblib', scalar='models/zksense_scalar.joblib')
    with open('../../trace/BatteryLab3/android-log-new') as fp:
        count = 0
        for line in fp:
            count += 1
            if count > 1000:
                break

            data = line.split(',')
            if len(data) != 12 and len(data) != 9:
                continue
            ts = float(data[0]) / 1000
            app = data[1]
            if app != 'com.hualai':
                continue
            sensor = data[2]
            if sensor == 'GYR' or sensor == 'UAC':
                sensor_values = [float(d) for d in data[3:9]]
                new_data = {
                    'ts': ts,
                    'app': app,
                    'sensor': sensor,
                    'sensor_values': sensor_values
                }
                # print('new_data', count, new_data)
                fiat_handler.new_data(new_data)