#   Copyright (C) 2013-2014 Computer Sciences Corporation
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import os
import kazoo.client
import kazoo.handlers.gevent
import gevent.coros
from zbase62 import zbase62
import ezRPKazoo
import ezRPRegistration
import ezRPConfigNginx
from ezRPCertStore import EzRPCertStore, EzRPCertStoreException
import ezRPConfig as gConfig

from ezconfiguration.helpers import AccumuloConfiguration

from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

from ezbake.reverseproxy import EzReverseProxy
from ezbake.reverseproxy.ttypes import *
from ezbake.frontend.thrift.ttypes import EzFrontendCertException


'''
Module to interface with Zookeeper. Zookeeper maintains the registration.
'''

sslconfig_node = lambda x : os.path.join(ezRPKazoo.KZSSLCONFLOC, x)


class EzReverseProxyHandler(object):
  def __init__(self, logger):
    self._logger = logger
    
    self.kz = kazoo.client.KazooClient(gConfig.zk, logger=self._logger, handler=kazoo.handlers.gevent.SequentialGeventHandler())
    self.kz.start()
    self.kz.ensure_path(ezRPKazoo.KZLOCKFILE)
    self.kz.ensure_path(ezRPKazoo.KZCONFLOC)
    self.kz.ensure_path(ezRPKazoo.KZWATCHLOC)
    self.kz.ensure_path(ezRPKazoo.KZSSLCONFLOC)

    accConfig = AccumuloConfiguration(gConfig.ezproperties)
    self.ac = EzRPCertStore(host=accConfig.getProxyHost(),
                            port=accConfig.getProxyPort(),
                            user=accConfig.getUsername(),
                            password=accConfig.getPassword(),
                            privateKey=gConfig.ez_keyfile,
                            logger=self._logger)
    self.lock = gevent.coros.Semaphore()


  def ping(self):
    self._logger.info("thrift interface received a ping()")
    rtn = True
    if gConfig.clientService.exception:
        self._logger.error("Error in thrift service greenlet: {0}".format(gConfig.clientService.exception))
        rtn = False
    if gConfig.zkMonitor.exception:
        self._logger.error("Error in zookeeper monitor greenlet: {0}".format(gConfig.zkMonitor.exception))
        rtn = False
    if gConfig.cfgGreenlet.exception:
        self._logger.error("Error in configuration change greenlet: {0}".format(gConfig.cfgGreenlet.exception))
        rtn = False
    if gConfig.wGreenlet.exception:
        self._logger.error("Error in shutdown monitor greenlet: {0}".format(gConfig.wGreenlet.exception))
        rtn = False

    return rtn

  def _serializeUpstreamServerRegistration(self, registration):
      transport = TTransport.TMemoryBuffer()
      protocol = TBinaryProtocol.TBinaryProtocol(transport)
      registration.write(protocol)
      return transport.getvalue()

  def _validateUpstreamServerRegistration(self,registration):
    # eventually this will validate the user facing hostname
    ezRPRegistration.get_ngx_server_name(registration)

    # eventually this will validate the user facing location
    ezRPRegistration.get_ngx_location(registration)

    # validates upstream portnumber - not yet host
    ezRPRegistration.getUpstreamHostAndPort(registration)

    # eventually will validate the upstream path
    ezRPRegistration.getUpstreamPath(registration)

    # validate timeout and timeoutTries
    try:
      assert registration.timeout > 0
      assert registration.timeout <=120
    except:
          raise EzReverseProxy.RegistrationInvalidException("timeout: %d not in range [1,120]" % (registration.timeout))
    try:
      assert registration.timeoutTries > 0
      assert registration.timeoutTries <=10
    except:
          raise EzReverseProxy.RegistrationInvalidException("timeoutTries: %d not in range [1,10]" % (registration.timeoutTries))

  def _validateNoConflictingUpstreamPath(self,registration):

    # the node in zk has 3 parts base62 encoded parts separated by _
    # see getNodeName for details
    matchingPrefix = ezRPRegistration.getNodeName(registration).rsplit('_',1)[0]+'_'
    basePrefix = matchingPrefix.split('_')[0]+'_'
    with self.lock:
        allConfigs = self.kz.get_children(ezRPKazoo.KZCONFLOC)
    sameUserFacingConfigs = [x for x in allConfigs if x.startswith(basePrefix)]

    # if there aren't any existing nodes in zk that have the same UserFacingPrefix
    # then we're OK to create one with any upstream path, and can just return here
    if len(sameUserFacingConfigs) > 0:
        # if one or more of the existing nodes with the same UserFacingPrefix has
        # a different upstream path, throw an invalid registration exception
        collidingConfigs = [x for x in sameUserFacingConfigs if not x.startswith(matchingPrefix)]
        if len(collidingConfigs) > 0:
            raise EzReverseProxy.RegistrationInvalidException("that UserFacingUrlPrefix is already registered with a different UpstreamPath")

  def _isServerUnique(self, registration):
     encodedServceNamePrefix = ezRPRegistration.getNodeName(registration).rsplit('_',1)[0]+'_'
     allConfigs = self.kz.get_children(ezRPKazoo.KZCONFLOC)
     return False if (len([x for x in allConfigs if x.startswith(encodedServceNamePrefix)]) > 1) else True

  def addUpstreamServerRegistration(self, registration):
    """
    Parameters:
     - registration
    """
    self._logger.info("thrift interface received a call to addUpstreamServerRegistration with a registration value of %s" % (registration))
    self._validateUpstreamServerRegistration(registration)
    self._validateNoConflictingUpstreamPath(registration)
    nodeName = ezRPKazoo.KZCONFLOC + '/' + ezRPRegistration.getNodeName(registration)
    nodeData = self._serializeUpstreamServerRegistration(registration)

    with self.lock:
        lock = self.kz.Lock(ezRPKazoo.KZLOCKFILE,"another contender")
        with lock:
            self._logger.info("addUpstreamServerRegistration registering")
            if not self.kz.exists(nodeName):
              self._logger.info("Adding node in zookeeper\n\tNode Name: %s\n\tNode Data:%s" % (nodeName,nodeData))
              self.kz.create(nodeName,nodeData)
            else:
              self.kz.set(nodeName,nodeData)
              self._logger.info("Updating node in zookeeper\n\tNode Name: %s\n\tNode Data:%s" % (nodeName,nodeData))
            self.kz.set(ezRPKazoo.KZWATCHLOC, str(gConfig.current_milli_time()))

  def removeUpstreamServerRegistration(self, registration):
    """
    Parameters:
     - registration
    """
    self._logger.info("thrift interface received a call to removeUpstreamServerRegistration with a registration value of %s" % (registration))
    self._validateUpstreamServerRegistration(registration)
    self._validateNoConflictingUpstreamPath(registration)
    nodeName =  ezRPKazoo.KZCONFLOC + '/' + ezRPRegistration.getNodeName(registration)
    serverName = ezRPRegistration.get_ngx_server_name(registration)
    sslConfigNodeName = ezRPKazoo.KZSSLCONFLOC + '/' + serverName
    with self.lock:
        lock = self.kz.Lock(ezRPKazoo.KZLOCKFILE,"another contender")
        with lock:
            if not self.kz.exists(nodeName):
              raise EzReverseProxy.RegistrationNotFoundException("no registration found for %s" % (nodeName))
            else:
              self._logger.info("removeUpstreamServerRegistration removing %s" % (nodeName))
              self.kz.delete(nodeName)
              if self.kz.exists(sslConfigNodeName) and self._isServerUnique(registration):
                  try:
                      #remove certs if server registration is unique
                      self.kz.delete(sslConfigNodeName)
                      self.ac.remove(serverName)
                      self._logger.info("removed certs for server %s" % serverName)
                  except EzRPCertStoreException as ex:
                      self._logger.exception('Exception in removing certs for server %s' % serverName)
              self.kz.set(ezRPKazoo.KZWATCHLOC, str(gConfig.current_milli_time()))

  def removeReverseProxiedPath(self, UserFacingUrlPrefix):
    """
    Parameters:
     - UserFacingUrlPrefix
    """
    self._logger.info("thrift interface received a call to removeReverseProxiedPath with a path value of %s" % UserFacingUrlPrefix)
    prefixToRemove = zbase62.b2a(UserFacingUrlPrefix)+ "_"
    with self.lock:
        allNodes = self.kz.get_children(ezRPKazoo.KZCONFLOC)
        fileNamesToRemove = [x for x in allNodes if x.startswith(prefixToRemove)]
        for fn in fileNamesToRemove:
            self._logger.info("removeReverseProxiedPath is deleting %s from zookeeper" % (ezRPKazoo.KZCONFLOC+'/'+fn))
            self.kz.delete(ezRPKazoo.KZCONFLOC+'/'+fn)
        if len(fileNamesToRemove) > 0:
            self.kz.set(ezRPKazoo.KZWATCHLOC, str(gConfig.current_milli_time()))

  def removeAllProxyRegistrations():
    self._logger.log("thrift interface received a call to removeAllProxyRegistration")
    allNodes = self.kz.get_children(ezRPKazoo.KZCONFLOC)
    with self.lock:
        for fn in allNodes:
            self._logger.log("removeAllProxyRegistrations is deleting %s from zookeeper" % (ezRPKazoo.KZCONFLOC+'/'+fn))
            self.kz.delete(ezRPKazoo.KZCONFLOC+'/'+fn)
            self.kz.set(ezRPKazoo.KZWATCHLOC, str(gConfig.current_milli_time()))

  def isUpstreamServerRegistered(self, registration): #UpstreamServerRegistration
    '''
        Does not verify timout and  timeoutTries match
    '''
    self._logger.info("thrift interface received a call to isUpstreamServerRegistered with a registration value of %s" % (registration))
    nodeName =  ezRPKazoo.KZCONFLOC + '/' + ezRPRegistration.getNodeName(registration)
    with self.lock:
        if self.kz.exists(nodeName):
            return True
    return False

  def isReverseProxiedPathRegistered(self, UserFacingUrlPrefix): #string
    self._logger.info("thrift interface received a call to isReverseProxiedPathRegistered with a path value of %s" % (UserFacingUrlPrefix))
    prefix = zbase62.b2a(UserFacingUrlPrefix)+ "_"
    with self.lock:
        allNodes = self.kz.get_children(ezRPKazoo.KZCONFLOC)
    matchingFilenames = [x for x in allNodes if x.startswith(prefix)]
    if len(matchingFilenames):
        return True
    return False

  def getAllUpstreamServerRegistrations(self):
    self._logger.info("thrift interface received a call to getAllUpstreamServerRegistrations")
    with self.lock:
        configurer = ezRPConfigNginx.Configurer(self.kz, self.ac, self._logger)
        rtn =  configurer.getAllRegistrations()
    return rtn

  def shutdown(self):
     self._logger.info("thrift interface received a call to shutdown")
     gConfig.clientService.kill()
     gevent.sleep()

  def addServerCerts(self, serverName, info):
     self._logger.info("thrift interface recevied a call to addServerCerts - %s" % (serverName))
     if serverName is None or not isinstance(serverName, basestring):
         raise EzFrontendCertException(message="Error in adding server cert. serverName must be a STRING")
     if info is None or info.certificateContents is None or info.keyContents is None:
         raise EzFrontendCertException(message="Error in adding server cert. info, info.certificateContents, info.keyContents should not be None.")
     if not isinstance(info.certificateContents, str) or not isinstance(info.keyContents, str):
         raise EzFrontendCertException(message="Error in adding server cert. info.certificateContents and info.keyContents must be a STRING")
     try:
         self.ac.put(serverName, info.certificateContents, info.keyContents)
         self.kz.ensure_path(sslconfig_node(serverName))
     except Exception as e:
         self._logger.exception("Exception in adding server certs for %s: %s" % (serverName, str(e)))
         raise EzFrontendCertException(message="Internal error in adding server cert for %s." % (serverName))

  def removeServerCerts(self, serverName):
     self._logger.info("thrift interface recevied a call to removeServerCerts - %s" % serverName)
     if serverName is None or not isinstance(serverName, basestring):
         raise EzFrontendCertException(message="Error in removing server cert. serverName must be a STRING")
     try:
         self.ac.remove(serverName)
         self.kz.delete(sslconfig_node(serverName))
     except Exception as e:
         self._logger.exception("Exception in removing server certs for %s: %s\n%s" % (serverName, str(e)))
         raise EzFrontendCertException(message="Internal error in removing server cert for %s." % (serverName))

  def serverCertsExists(self, serverName):
     self._logger.info("thrift interface recevied a call to serverCertsExists - %s" % serverName)
     if serverName is None or not isinstance(serverName, basestring):
         raise EzFrontendCertException(message="Error in checking server cert. serverName must be a STRING")
     try:
         return self.ac.exists(serverName)
     except Exception as e:
         self._logger.exception("Exception in checking server certs for %s: %s\n%s" % (serverName, str(e)))
         raise EzFrontendCertException(message="Internal error in checking server cert for %s." % (serverName))


