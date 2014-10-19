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
import signal
import ezRPConfig as gConfig
from shutil import rmtree
from shutil import copyfile
from shutil import copytree
from shutil import copy
from string import Template
import subprocess


"""
Module to setup and tear Nginx configuration
"""

def copyMimeConfig():
    copyfile(gConfig.mimeTemplate,gConfig.mimeConfig)
    
def createMainConfigFile():
    with open(gConfig.mainConfigTemplate) as template:
        template_str = Template(template.read())
        if gConfig.args.ngx_workers < 2:
            nworkers = 2
        else:
            nworkers = gConfig.args.ngx_workers

        config = template_str.substitute(workers=nworkers,
                                         user=gConfig.nginx_worker_username,
                                         logdir=gConfig.logDirectory,
                                         ezngx_mod_log_prop=gConfig.eznginxmoduleLogProp,
                                         ezconfig_override_dir=gConfig.ezconfig_dir,
                                         confdir=gConfig.confdDirectory,
                                         proxy_ssl_ciphers=gConfig.ezproxyciphers,
                                         proxy_ssl_verify_depth=gConfig.max_ca_depth)

        with open(gConfig.mainConfig, 'w') as mainConfigFile:
            mainConfigFile.write(config)
            
def copyManualConfigs(logger):
    if os.path.exists(gConfig.manualDirectory) and os.path.isdir(gConfig.manualDirectory):
        for filename in os.listdir(gConfig.manualDirectory):
            if filename != "servers.conf":
                src = os.path.join(gConfig.manualDirectory,filename)
                dst = os.path.join(gConfig.confdDirectory,filename)
                logger.debug("src: %s  dst: %s" % (src,dst))
                copyfile(src,dst)

def createCAChainFile():
    with open(gConfig.ssl_cafile,'wb') as outfile:
        for root,dirs,files in os.walk(gConfig.ssl_cadir):
            for file in files:
                with open(os.path.join(root, file),'rb') as infile:
                    outfile.write(infile.read())

def createEzNginxModuleLogProps():
    if os.path.isfile(gConfig.eznginxmoduleLogProp):
        return
    #create default log properties configuration for eznginx
    with open(gConfig.eznginxmoduleLogProp,'w') as logprop:
        logprop.write('log4j.rootLogger=INFO, F\n')
        logprop.write('log4j.appender.F=org.apache.log4j.FileAppender\n')
        logprop.write('log4j.appender.F.file=%s\n' % (os.path.join(gConfig.logDirectory,'eznginx_module.log')))
        logprop.write('log4j.appender.F.append=true\n')
        logprop.write('log4j.appender.F.threshold=INFO\n')
        logprop.write('log4j.appender.F.layout=org.apache.log4j.PatternLayout\n')
        logprop.write('log4j.appender.F.layout.conversionPattern=\%d{ISO8601} \%5p [\%X{PID} - \%t] (\%l) - \%m\%n\n')

def nginx_basesetup(logger):
    '''
    Creates the working directory for nginx including the config directory,
    basic configuration, conf.d, and log directory.

    This is meant to be called after either nginx_cleanup_self()
    or nginx_cleanup(), so we can assume the directory doesn't already exist.
    '''

    os.makedirs(gConfig.workingDirectory)
    os.makedirs(gConfig.workingDirectory+'/logs')
    for dir in gConfig.ssl_server_certs_dirs:
      os.makedirs(dir)
    subprocess.call(['ln', '-sTf', gConfig.ssl_server_certs_dirs[0], gConfig.ssl_server_certs])
    #subprocess.call(["chown","-R",gConfig.nginx_worker_username+":"+gConfig.nginx_worker_username,gConfig.ezEtc])
    #subprocess.call(["chmod","o+rx",gConfig.workingDirectory])

    os.makedirs(gConfig.workingDirectory+'/html')
    #subprocess.call(["chmod","o+rx",gConfig.workingDirectory+'/html'])
   
    copyfile(gConfig.templateDir+'/favicon.ico',gConfig.workingDirectory+'/html/favicon.ico')
    #subprocess.call(["chmod","o+rx",gConfig.workingDirectory+'/html/favicon.ico'])

    copytree(gConfig.templateDir+'/ezbstatic',gConfig.workingDirectory+'/html/ezbstatic')
 
    for tmp in ['client_body_temp','fastcgi_temp','proxy_temp','scgi_temp','uwsgi_temp']:
        newdir=os.path.join(gConfig.workingDirectory,tmp)
        os.makedirs(newdir)
        #subprocess.call(["chown","-R",gConfig.nginx_worker_username+":"+gConfig.nginx_worker_username,newdir])

    if not os.path.isdir(gConfig.logDirectory):
        os.makedirs(gConfig.logDirectory)
    os.makedirs(gConfig.configDirectory)
    os.makedirs(gConfig.confdDirectory)

    copyMimeConfig()
    copy(gConfig.logrotateConfTemplate, gConfig.logDirectory)
    createMainConfigFile()
    copyManualConfigs(logger)
    createCAChainFile()
    createEzNginxModuleLogProps()

    open(gConfig.shutdownFile,'w').close()

    # start nginx
    # open a file for its stdout
    with open(os.path.join(gConfig.logDirectory,'stdout'),'w') as nginxStdout:
        with open(os.path.join(gConfig.logDirectory,'stderr'),'w') as nginxStderr:
            nginxArgs = [gConfig.nginx,'-c',gConfig.mainConfig,'-p',gConfig.workingDirectory]
            gConfig.nginxInstance = subprocess.Popen(nginxArgs,stdout=nginxStdout,stderr=nginxStderr)
    logger.info("launched nginx with pid %d" % (gConfig.nginxInstance.pid))


def nginx_cleanup_self(masterPID=0):
    '''
    Function meant to gracefully shut down an instance of nginx and delete the
    nginx working directory. The SIGQUIT signal is sent to the PID (assumed
    to be the master ngix PID).

    If masterPID is not provided, or is set to 0, nginx will not be shutdown,
    rather the working directory will simply be removed. This can be used at
    startup to ensure a clean working directory.
    '''

    if masterPID != 0:
        # os.kill is a misnomer -- only way to send a signal in python
        os.kill(masterPID, signal.SIGQUIT)

    # recursively remove the workingDirectory
    try:
        rmtree(gConfig.workingDirectory)
    except Exception as e:
        pass

def get_nginx_master_pid():
    with open(gConfig.nginxPidFile) as pidfile:
        pidstr = pidfile.read()
        return int(pidstr)
    return 0

def get_nginx_worker_pids():
    rtn = []
    s = subprocess.Popen('ps -ef | grep "nginx: worker process" | grep -v grep', shell=True, stdout=subprocess.PIPE)
    for line in s.stdout:
        pid = int(line.split()[1])
        rtn.append(pid)
    return rtn

def nginx_cleanup():
    '''
    Finds all master nginx processes on the box and kills them.

    Cleans up the single workindDirectory relevant to this execution
    of the reverse proxy.
    '''
    # find and kill all instances of nginx master
    count = 0
    s = subprocess.Popen('ps -ef | grep "nginx: master process" | grep -v grep', shell=True, stdout=subprocess.PIPE)
    for line in s.stdout:
        pid = int(line.split()[1])
        # os.kill is a misnomer -- only way to send a signal in python
        os.kill(pid, signal.SIGQUIT) # 3 is sigquit
        count += 1

    if count > 1:
        log("Signaled %d nginx masters to stop, but can only cleanup 1 working directory: %s" % (count, gConfig.workingDirectory))

    # recursively remove the workingDirectory
    try:
        rmtree(gConfig.workingDirectory)
    except Exception as e:
        pass

