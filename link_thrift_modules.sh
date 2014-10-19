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

function create_module_links() {
    local dir=($@)
    for d in ${dir[@]}; do
        module=`basename $d`
        path=${d:0:${#d}-1}
        echo_and_execute_cmd "ln -sTf ${path} ${module}"
    done
}


#link test_server(ezfrontend-ui) thrift files
echo_and_execute_cmd "cd utils/test_server"
echo_and_execute_cmd "ln -sf ../../ezReverseProxy/TSSLSocket"
echo_and_execute_cmd "ln -sf ../../ezReverseProxy/pyaccumulo"
echo_and_execute_cmd "ln -sf ../../ezReverseProxy/modules"
echo_and_execute_cmd "cd ${CWD}"

