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


fail() {
    echo $1
    exit 1
}

function echo_and_execute_cmd() {
    local cmd=$1
    echo ${cmd}
    ${cmd} || fail "Error in running: ${cmd}"
}


#   
CWD=$(pwd)
EZBAKE_DIR="/vagrant/ezbake"

NAR_LIB_EZBAKE_BASE_THRIFT="${EZBAKE_DIR}/ezbake-base-thrift"
NAR_LIB_EZSECURITY_THRIFT="${EZBAKE_DIR}/ezbake-security-thrift"
NAR_LIB_EZREVERSEPROXY_THRIFT="${EZBAKE_DIR}/ezbake-reverseproxy-thrift"
NAR_LIB_EZLRUCACHE="${EZBAKE_DIR}/ezlrucache"
NAR_LIB_THRIFT_UTILS="${EZBAKE_DIR}/thriftutils/cpp"
NAR_LIB_EZCONFIGURATION="${EZBAKE_DIR}/ezbake-configuration/api/cpp"
NAR_LIB_EZDISCOVERY="${EZBAKE_DIR}/ezbake-discovery/servicediscovery/cpp"
NAR_LIB_EZSECURITY_CLIENT="${CWD}/ezcppsecurity"
NAR_LIB_EZNIGNX_MODULE="${CWD}/eznginxmodule"
EZNGINX_BUILD_PATH="${CWD}/eznginx"
EZNGINX_BUILD_LIB_PATH="${EZNGINX_BUILD_PATH}/libs"


