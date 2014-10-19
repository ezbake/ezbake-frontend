#!/bin/bash
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

. common.sh

#
quick_mode=false
if [ "$1" == "--quick-mode" ]; then
    quick_mode=true
    echo "building eznginx-ezsecurity in QUICK MODE - only eznginx build"
fi

#
MVN_CMD="mvn clean install -D maven.test.skip=true"
MVN_NAR_FLAG="-P narbuild"

##buid eznginx libraries
echo "-- building ezconfiguration"
echo_and_execute_cmd "cd ${NAR_LIB_EZCONFIGURATION}"
echo_and_execute_cmd "${MVN_CMD}"

#echo "-- building ezdiscovery"
echo_and_execute_cmd "cd ${NAR_LIB_EZDISCOVERY}"
echo_and_execute_cmd "${MVN_CMD}"

#echo "-- building ezlrucache"
echo_and_execute_cmd "cd ${NAR_LIB_EZLRUCACHE}"
echo_and_execute_cmd "${MVN_CMD}"

#echo "-- building ezbake-base-thrift"
#echo_and_execute_cmd "cd ${NAR_LIB_EZBAKE_BASE_THRIFT}"
#echo_and_execute_cmd "${MVN_CMD} ${MVN_NAR_FLAG}"

#echo "-- building ezbakesecurity-thrift"
#echo_and_execute_cmd "cd ${NAR_LIB_EZSECURITY_THRIFT}"
#echo_and_execute_cmd "${MVN_CMD} ${MVN_NAR_FLAG}"

echo "-- building thrift-utils"
echo_and_execute_cmd "cd ${NAR_LIB_THRIFT_UTILS}"
echo_and_execute_cmd "${MVN_CMD}"

echo "-- building ezsecurity-client"
echo_and_execute_cmd "cd ${NAR_LIB_EZSECURITY_CLIENT}"
echo_and_execute_cmd "${MVN_CMD}"

if [ $quick_mode = false ]; then
    echo "-- configuring nginx with module dependencies"
    echo_and_execute_cmd "cd ${EZNGINX_BUILD_PATH}"
    echo_and_execute_cmd "./configure.sh"
fi

echo "-- building eznginx module library"
echo_and_execute_cmd "cd ${NAR_LIB_EZNIGNX_MODULE}"
echo_and_execute_cmd "${MVN_CMD}"

echo "-- copying eznginx libraries"
ezNginxLibs="${NAR_LIB_EZNIGNX_MODULE}/target/nar/*amd64-Linux-gpp-shared/lib/amd64-Linux-gpp/shared/lib*"
ezNginxLibFiles=`find ${ezNginxLibs} -name "*.so"`
#echo_and_execute_cmd "cp -fv ${ezNginxLibs} ${EZNGINX_BUILD_LIB_PATH}"
for f in ${ezNginxLibFiles}; do
    echo_and_execute_cmd "cp -f ${f} ${EZNGINX_BUILD_LIB_PATH}"
done
echo_and_execute_cmd "cd ${EZNGINX_BUILD_LIB_PATH}"
for f in ${ezNginxLibFiles}; do
    libfile=${f##*/}
    liblink=`echo ${libfile} | sed 's/^\(.*\)-[0-9\.]\+.*$/\1.so/g'`
    echo_and_execute_cmd "ln -sf ${libfile} ${liblink}"
    echo_and_execute_cmd "chmod +x ${libfile}"
done
echo_and_execute_cmd "cd ${CWD}"


echo "-- building eznginx module application"
echo_and_execute_cmd "cd ${EZNGINX_BUILD_PATH}"
echo_and_execute_cmd "./build.sh"
echo_and_execute_cmd "cd ${CWD}"

echo_and_execute_cmd "./link_thrift_modules.sh"

