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

rm -rf ezfrontend
rm -ff Ez*rpm
cp -rf container-nolinks ezfrontend
rm -rf ezfrontend/etc
sudo rm -f ezfrontend/logs/*
sudo rm -rf ezfrontend/wd
CERTSNAME=EzFrontend-user-facing-certs
FENAME=EzFrontend
LIBNAME=${FENAME}-libs
CANAME=EzFrontend-user-ca-certs
UINAME=EzFrontend-UI
VERSION=2.0
RELEASE=`date +"%Y%m%d%H%M"`
touch ezfrontend/config/ssl/server/rpminfo_$CERTSNAME-$VERSION-$RELEASE
touch ezfrontend/rpminfo_$FENAME-$VERSION-$RELEASE
fpm -s dir -t rpm -n $CERTSNAME -v $VERSION --iteration $RELEASE  ezfrontend/config/ssl/server=/opt/ezfrontend/config/ssl/
rm -rf ezfrontend/config/ssl/server
fpm -s dir -t rpm -n $CANAME -v $VERSION --iteration $RELEASE  ezfrontend/config/ssl/user_ca_files=/opt/ezfrontend/config/ssl/
rm -rf ezfrontend/config/ssl/user_ca_files

sudo rm -rf /tmp/ezfrontend-pkg
sudo mkdir -p /tmp/ezfrontend-pkg/opt
sudo mkdir -p /tmp/ezfrontend-pkg/init_scripts
sudo cp -a ezfrontend /tmp/ezfrontend-pkg/opt
sudo chown -R ezfrontend:ezfrontend /tmp/ezfrontend-pkg/opt/ezfrontend
sudo chmod -R go-rwx /tmp/ezfrontend-pkg/opt/ezfrontend/app
sudo chmod 700 /tmp/ezfrontend-pkg/opt/ezfrontend/start
sudo chmod 700 /tmp/ezfrontend-pkg/opt/ezfrontend/stop
sudo cp -a service-scripts/* /tmp/ezfrontend-pkg/init_scripts
sudo chown -R ezfrontend:ezfrontend /tmp/ezfrontend-pkg/init_scripts/ezfrontend
sudo fpm -s dir -t rpm --rpm-use-file-permissions  --directories=/opt/ezfrontend -n $FENAME -v $VERSION --iteration $RELEASE --config-files /opt/ezfrontend/config/eznginx.properties /tmp/ezfrontend-pkg/opt/=/opt /tmp/ezfrontend-pkg/init_scripts/ezfrontend/=/etc/init.d

##temp generation of shared libraries rpm
sudo chmod -R 755 eznginx/libs/
sudo fpm -s dir -t rpm -n $LIBNAME -v $VERSION --iteration $RELEASE eznginx/libs=/opt/ezfrontend
###


# test server
cd utils
sudo rm -rf test_server_package
cp -rf --dereference test_server test_server_package
rm test_server_package/ezfrontendui.py
pyinstaller --hidden-import=greenlet --hidden-import=ezbake.reverseproxy test_server/ezfrontendui.py
rm -f server.spec
mv dist/ezfrontendui test_server_package/
rm -rf dist
rm -rf build
touch test_server_package/rpminfo_$UINAME-$VERSION-$RELEASE
chmod o-x test_server_package/start
chmod o-x test_server_package/stop
chmod o-x test_server_package/ezfrontendui/ezfrontendui
rm -f test_server_package/nohup.out
rm -f test_server_package/README
rm -f test_server_package/pidfile
rm -f test_server_package/client.py
sudo chmod 700 test_server_package/start
sudo chmod 700 test_server_package/stop
sudo chmod 700 test_server_package/ezfrontendui/ezfrontendui
sudo chmod 600 test_server_package/*.yaml

sudo rm -rf /tmp/test_server_package
sudo cp -rf test_server_package /tmp/
sudo chown -R ezfrontendui:ezfrontendui /tmp/test_server_package

sudo chown -R ezfrontendui:ezfrontendui /tmp/ezfrontend-pkg/init_scripts/ezfrontend-ui

sudo fpm -s dir -t rpm --rpm-use-file-permissions -n $UINAME -v $VERSION --iteration $RELEASE --config-files /opt/ezfrontend-ui/configurations.yaml --config-files /opt/ezfrontend-ui/authorized_users.yaml --config-files /opt/ezfrontend-ui/test_configurations.yaml  /tmp/test_server_package/=/opt/ezfrontend-ui /tmp/ezfrontend-pkg/init_scripts/ezfrontend-ui/=/etc/init.d
mv *.rpm ../
cd ..

