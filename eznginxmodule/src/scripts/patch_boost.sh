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


CWD=$(pwd)
BASE_DIR=${1}
PATCH_DIR=${BASE_DIR}/target/nar/boost-includes-1.41.0-noarch/include/boost/property_tree/detail/
PATCH_FILE=${BASE_DIR}/src/scripts/boost_json.patch

cd ${PATCH_DIR}
patch --verbose < ${PATCH_FILE}
echo "Patched file"
cd ${CWD}

