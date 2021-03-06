#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

import socket
import fixtures
import subprocess
from util import retry
from mockredis import mockredis
from mockzoo import mockzoo
from mockifmap import mockifmap
import redis
import time
import urllib2
import copy
import os
import json
from operator import itemgetter
from utils.vnc_introspect_utils import VNCApiInspect

class SvcMonitor(object):
    def __init__(self, config_fixture, logger):
        self._instance = None
        self._logger = logger
        self._config_fixture = config_fixture
        self._http_port = ConfigFixture.get_free_port()

    def start(self):
        assert(self._instance == None)
        self._log_file = '/tmp/svcmonitor.messages.' + str(self._http_port)
        args = ['python', self._config_fixture.builddir + \
                '/config_test/lib/python2.7/site-packages/svc_monitor/svc_monitor.py',
                '--http_server_port', str(self._http_port),
                '--ifmap_username', 'svc-monitor',
                '--ifmap_password', 'svc-monitor',
                '--api_server_port', str(self._config_fixture.apiserver.port),
                '--log_file', self._log_file,
                '--log_level', "SYS_DEBUG",
                "--ifmap_server_port", str(self._config_fixture.ifmap.port),
                "--ifmap_server_ip", "127.0.0.1",
                '--zk_server_ip', '127.0.0.1:' +
                str(self._config_fixture.zoo.port),
                '--cassandra_server_list', '127.0.0.1:' +
                str(self._config_fixture.cassandra_port)]

        self._instance = subprocess.Popen(args, 
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
        self._logger.info('Setting up SvcMonitor: %s' % ' '.join(args))
    # end start

    def stop(self):
        if self._instance is not None:
            self._logger.info('Shutting down SvcMonitor 127.0.0.1:%d' 
                              % (self._http_port))
            self._instance.terminate()
            (op_out, op_err) = self._instance.communicate()
            ocode = self._instance.returncode
            if ocode != 0:
                self._logger.info('SvcMonitor returned %d' % ocode)
                self._logger.info('SvcMonitor terminated stdout: %s' % op_out)
                self._logger.info('SvcMonitor terminated stderr: %s' % op_err)
            subprocess.call(['rm', self._log_file])
            self._instance = None
    # end stop
        
class Schema(object):
    def __init__(self, config_fixture, logger):
        self._instance = None
        self._logger = logger
        self._config_fixture = config_fixture
        self._http_port = ConfigFixture.get_free_port()

    def start(self):
        assert(self._instance == None)
        self._log_file = '/tmp/schema.messages.' + str(self._http_port)
        args = ['python', self._config_fixture.builddir + \
                '/config_test/lib/python2.7/site-packages/schema_transformer/to_bgp.py',
                '--http_server_port', str(self._http_port),
                '--ifmap_username', 'schema-transformer',
                '--ifmap_password', 'schema-transformer',
                '--api_server_port', str(self._config_fixture.apiserver.port),
                '--log_file', self._log_file,
                '--log_level', "SYS_DEBUG",
                "--ifmap_server_port", str(self._config_fixture.ifmap.port),
                "--ifmap_server_ip", "127.0.0.1",
                '--zk_server_ip', '127.0.0.1:' +
                str(self._config_fixture.zoo.port),
                '--cassandra_server_list', '127.0.0.1:' +
                str(self._config_fixture.cassandra_port)]

        self._instance = subprocess.Popen(args, 
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
        self._logger.info('Setting up Schema: %s' % ' '.join(args))
    # end start

    def stop(self):
        if self._instance is not None:
            self._logger.info('Shutting down Schema 127.0.0.1:%d' 
                              % (self._http_port))
            self._instance.terminate()
            (op_out, op_err) = self._instance.communicate()
            ocode = self._instance.returncode
            if ocode != 0:
                self._logger.info('Schema returned %d' % ocode)
                self._logger.info('Schema terminated stdout: %s' % op_out)
                self._logger.info('Schema terminated stderr: %s' % op_err)
            subprocess.call(['rm', self._log_file])
            self._instance = None
    # end stop
        
class ApiServer(object):

    def __init__(self, config_fixture, logger):
        self._instance = None
        self._logger = logger
        self._config_fixture = config_fixture
        self.port = ConfigFixture.get_free_port()
        self._http_port = ConfigFixture.get_free_port()
    def start(self, analytics_start_time=None):
        assert(self._instance == None)
        self._log_file = '/tmp/api.messages.' + str(self.port)
        bdir = self._config_fixture.builddir
        args = ['coverage', 'run', '-a', '-p',
                '--source=%s,%s' % \
                (bdir + '/config/api-server/vnc_cfg_api_server/',
                 bdir + '/config_test/lib/python2.7/site-packages/cfgm_common/'),
                '--omit=%s,%s,%s' % \
                (bdir + '/config/api-server/vnc_cfg_api_server/gen/*',
                 bdir + '/config_test/lib/python2.7/site-packages/cfgm_common/uve/*',
                 bdir + '/config/api-server/vnc_cfg_api_server/bottle*'),
                bdir + '/config/api-server/vnc_cfg_api_server/vnc_cfg_api_server.py',
                '--redis_server_port', str(self._config_fixture.redis_cfg.port),
                '--http_server_port', str(self._http_port),
                '--ifmap_username', 'api-server',
                '--ifmap_password', 'api-server',
                '--log_file', self._log_file,
                '--log_level', "SYS_DEBUG",
                '--listen_port', str(self.port),
                "--ifmap_server_port", str(self._config_fixture.ifmap.port),
                "--ifmap_server_ip", "127.0.0.1",
                '--zk_server_ip', '127.0.0.1:' +
                str(self._config_fixture.zoo.port),
                '--cassandra_server_list', '127.0.0.1:' +
                str(self._config_fixture.cassandra_port)]
        ShEnv = { 'COVERAGE_FILE' : '%s/config/.coverage' % bdir , 'PATH': os.environ['PATH']}
        self._instance = subprocess.Popen(args,env=ShEnv)
        self._logger.info('Setting up ApiServer: %s' % ' '.join(args))
    # end start

    def stop(self):
        if self._instance is not None:
            self._logger.info('Shutting down ApiServer 127.0.0.1:%d' 
                              % (self.port))
            self._instance.terminate()
            (op_out, op_err) = self._instance.communicate()
            ocode = self._instance.returncode
            if ocode != 0:
                self._logger.info('ApiServer returned %d' % ocode)
                self._logger.info('ApiServer terminated stdout: %s' % op_out)
                self._logger.info('ApiServer terminated stderr: %s' % op_err)
            subprocess.call(['rm', self._log_file])
            self._instance = None
    # end stop
        
class Redis(object):
    def __init__(self, builddir):
        self.port = ConfigFixture.get_free_port()
        self.builddir = builddir
        self.running = False
    # end __init__

    def start(self):
        assert(self.running == False)
        self.running = True
        mockredis.start_redis(self.port, self.builddir + '/testroot/bin/redis-server') 
    # end start

    def stop(self):
        if self.running:
            mockredis.stop_redis(self.port)
            self.running =  False
    #end stop

class Zookeeper(object):
    def __init__(self):
        self.port = ConfigFixture.get_free_port()
        self.running = False
    # end __init__

    def start(self):
        assert(self.running == False)
        self.running = True
        mockzoo.start_zoo(self.port) 
    # end start

    def stop(self):
        if self.running:
            mockzoo.stop_zoo(self.port)
            self.running =  False
    #end stop
# end class Zookeeper

class Ifmap(object):
    def __init__(self):
        self.port = ConfigFixture.get_free_port()
        self.running = False
    # end __init__

    def start(self):
        assert(self.running == False)
        self.running = True
        mockifmap.start_ifmap(self.port) 
    # end start

    def stop(self):
        if self.running:
            mockifmap.stop_ifmap(self.port)
            self.running =  False
    #end stop
# end class Ifmap

class ConfigFixture(fixtures.Fixture):
    def __init__(self, logger, builddir, cassandra_port):
        self.builddir = builddir
        self.cassandra_port = cassandra_port
        self.logger = logger

    def setUp(self):
        super(ConfigFixture, self).setUp()

        self.redis_cfg = Redis(self.builddir)
        self.redis_cfg.start()
        self.zoo = Zookeeper()
        self.zoo.start()
        self.ifmap = Ifmap()
        self.ifmap.start()

        self.apiserver = ApiServer(self,self.logger)
        self.apiserver.start()
        self.schema = Schema(self,self.logger)
        self.schema.start()

    @retry(delay=4, tries=5)  
    def verify_default_project(self):
        result = True
        try:
            vai = VNCApiInspect('127.0.0.1',self.apiserver.port)
            prj = vai.get_cs_project('default-domain','default-project')
            if len(prj['project']['virtual_networks']) != 3:
                result &= False
            self.logger.info("Verifying default-project: %s" % prj['project']['virtual_networks'])
        except:
            self.logger.error("Exception Verifying default-project")
            result &= False

        return result

    def cleanUp(self):
        super(ConfigFixture, self).cleanUp()

        self.ifmap.stop()
        self.apiserver.stop()
        self.schema.stop()
        self.zoo.stop()
        self.redis_cfg.stop()

    @staticmethod
    def get_free_port():
        cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cs.bind(("", 0))
        cport = cs.getsockname()[1]
        cs.close()
        return cport
        

