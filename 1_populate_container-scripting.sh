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


#pull static content with bower
bower update

# delete old
rm -rf container-scripting
# build new
mkdir container-scripting
cd container-scripting
ln -sf ../container_template/start
ln -sf ../container_template/stop
ln -sf ../container_template/config
ln -sf ../container_template/etc
mkdir app
ln -sf ../../ezReverseProxy app/ezReverseProxy
ln -sf ../../eznginx/nginx/objs/nginx app/nginx
ln -sf ../../ezReverseProxy/templates app/templates
if [ ! -d config/ssl/server ]; then
    mkdir config/ssl/server
fi
ln -sf ../../../../utils/dummy_certs/ezbake.io.key config/ssl/server/server.key
ln -sf ../../../../utils/dummy_certs/ezbake.io.crt config/ssl/server/server.crt
mkdir logs
cd ..

