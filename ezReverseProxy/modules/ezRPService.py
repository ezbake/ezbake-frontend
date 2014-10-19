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
import gevent
import gevent_inotifyx
import ezRPGreenlet
import ezRPConfig as gConfig

import ezdiscovery
from ezbake.reverseproxy.constants import SERVICE_NAME as EzFrontendServiceName


class EzReverseProxyService(object):
    def __init__(self, logger):
        self._logger = logger

    def run(self):
      glt = ezRPGreenlet.EzReverseProxyGreenlet(self._logger)
      self._logger.info("starting greenlet for thrift service...")
      clientGreenlet = gevent.spawn(glt.clientServiceGreenlet)
      self._logger.info("started")

      self._logger.info("starting greenlet to monitor zookeeper...")
      kzGreenlet = gevent.spawn(glt.kzMonitorGreenlet)
      self._logger.info("started")

      self._logger.info("starting greenlet to write out nginx configuration changes...")
      cfgProcessorGreenlet = gevent.spawn(glt.configurationChangeQueueGreenlet)
      self._logger.info("started")

      self._logger.info("starting greenlet to monitor for shutdown...")
      fd = gevent_inotifyx.init()
      wd = gevent_inotifyx.add_watch(fd, gConfig.shutdownFile, gevent_inotifyx.IN_DELETE)
      wGreenlet = gevent.spawn(glt.watchGreenlet, fd)
      self._logger.info("started")

      gConfig.addGreenlets(clientGreenlet, kzGreenlet, cfgProcessorGreenlet, wGreenlet)


      gevent.joinall([clientGreenlet])
      self._logger.warn("joined thrift service greenlet")
      gevent.joinall([kzGreenlet])
      self._logger.warn("joined zookeeper monitoring greenlet")
      gConfig.run = False
      while not gConfig.configurationChangeQueue.empty():
          print "queue not empty"
          gConfig.configurationChangeQueue.get()
          print "got"
          gConfig.configurationChangeQueue.task_done()
      print "joining conf queue"
      gConfig.configurationChangeQueue.join()
      self._logger.warn("joined configuration queue")
      gevent.joinall([cfgProcessorGreenlet])
      self._logger.warn("joined configuration change greenlet")
      gConfig.wGreenlet.join()
      self._logger.warn("joined shutdown monitor greenlet")
      ezdiscovery.connect(gConfig.zk)
      ezdiscovery.unregister_endpoint('system_services', EzFrontendServiceName, gConfig.internal_hostname, gConfig.thriftPort)
      ezdiscovery.disconnect()
      self._logger.warn("unregistering from discovery service")
