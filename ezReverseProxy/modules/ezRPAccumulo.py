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

from pyaccumulo import Accumulo, Mutation, Range
from pyaccumulo.iterators import *

class EzRPAccumulo(object):

    '''
    Class to save and retrieve certificates and keys from accumulo 
    '''
    def __init__(self, host="localhost", port=42424, user='root', password='secret'):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.table = 'ezfrontend'
        self.connection =  Accumulo(self.host, self.port, self.user, self.password)

    def put(self, host_name, pem_str, isCert=False):
        '''
        Puts the pem_str in accumulo table.
        isCert==True, if pem_str is Certificate.
        isCert==False, if pem_str is Key.
        '''

        if not self.connection.table_exists(self.table):
           self.connection.create_table(self.table)
        writer = self.connection.create_batch_writer(self.table)
       
        if isCert:
           row = host_name
           mut = Mutation(row)
           mut.put(cf="cert", cq="pem", val=pem_str)
           writer.add_mutation(mut)
           writer.close()
        else:
           row = host_name
           mut = Mutation(row)
           mut.put(cf="key", cq="pem", val=pem_str)
           writer.add_mutation(mut)
           writer.close()
        
    def get(self, host_name, isCert=False):
        '''
        Gets the pem string, given the type and fqn.
        isCert==True, if pem_str is Certificate.
        isCert==False, if pem_str is Key.
        '''

        if not self.connection.table_exists(self.table):
           self.connection.create_table(self.table)
        
        no_value=''
        row = host_name
        
        if isCert:
           for entry in self.connection.scan(self.table, None, cols=[["cert"]]):
               if entry.row == row :
                 return str(entry.val)
    
        else:
            for entry in self.connection.scan(self.table, None, cols=[["key"]]):
               if entry.row == row :
                 return str(entry.val)
        return no_value
        

    def exist(self, host_name):
        '''
        return True if the host_name is in the table
        '''
        s = self.get(host_name)
        if len(s) > 0:
           return True
        else:
           return False
        
    def delete(self, host_name):
        '''
        Deletes the cert and key from table given the host_name
        '''
        if not self.connection.table_exists(self.table):
           self.connection.create_table(self.table)
        writer = self.connection.create_batch_writer(self.table)

        mut = Mutation(host_name)
        mut.put(cf="cert", cq="pem", is_delete=True)
        mut.put(cf="key", cq="pem", is_delete=True)
        writer.add_mutation(mut)
        writer.close()

