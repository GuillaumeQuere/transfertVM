# -*- coding: utf-8 -*-

import spur

from driver import Driver
from . import ssh
from apacheChapter3 import ApacheChapter3


class ApacheCISProbe(Driver):
    host = None
    port = None
    username = None
    password = None
    private_key = None
    private_key_passphrase = None
    config_apache = None
    apache = None
    ssh_client = None
    executor = None
    list_exec_method = None

    def rollback(self, inputs=None):
        self.result.put_value('ERROR', 'Contact Moon Cloud admin')
        return False

    def parse_input(self,inputs=None):
        config = self.testinstances.get('config')
        assert config is not None
        host = config.get('host')
        assert host is not None
        port = config.get('port', '22')
        list_exec_method = config.get('exec_method')
        assert list_exec_method is not None

        ssh_creds = self.testinstances.get('connect_to_server')
        assert ssh_creds is not None
        username = ssh_creds.get('username')
        assert username is not None
        password = ssh_creds.get('password', None)
        private_key = ssh_creds.get('private_key', None)
        private_key_passphrase = ssh_creds.get('private_key_passphrase', None)
        if password is None and private_key is None:
            self.result.put_value('CONFIG_ERROR', 'Missing SSH credentials')
            raise Exception()
        op_system = ssh_creds.get('os',None)
        assert op_system is not None
        # Method to be executed
        caract = self.testinstances.get('caracteristic')
        if op_system in ["ubuntu", "debian", "centos"]:
            self.config_apache = caract.get(op_system)
        else:
            self.result.put_value('CONFIG_ERROR', 'Unknown operating system')
            raise Exception()
        self.host = host
        self.port = port
        self.username = username
        self.list_exec_method = list_exec_method
        if password is not None and password != '':
            self.password = password
        elif private_key is not None:
            self.private_key = private_key
            self.private_key_passphrase = private_key_passphrase
        return True

    def check_ssh_conn(self, inputs=None):
        try:
            self.ssh_client = ssh.CustomSshShell(hostname=self.host,
                                                 username=self.username,
                                                 password=self.password,
                                                 port=self.port,
                                                 private_key=self.private_key,
                                                 private_key_passphrase=self.private_key_passphrase,
                                                 missing_host_key=spur.ssh.MissingHostKey.warn,
                                                 shell_type=spur.ssh.ShellTypes.sh
                                                 )
            self.ssh_client.connect_ssh()
        except Exception as e:
            # log the exception
            import traceback
            traceback.print_exc(e)
            self.result.put_value('SSH_ERROR', 'Fail to connect to the server')
        return True

    def action(self,inputs=None):
        try:
            self.apache = ApacheChapter3(apache_bin=self.config_apache["apache_bin"],
                                         apache_dir=self.config_apache["apache_dir"],
                                         apache_conf=self.config_apache["apache_conf"],
                                         ssh_client=self.ssh_client)
            self.executor = ApacheCISExecutor(self.apache, self.list_exec_method)
            # start the execution.
            self.executor.action()
            result = self.executor.result
            for key, value in result['extradata'].items():
                self.result.put_value(key, value)
            return result['driver_result']
        except Exception as e:
            # ok there was an error, return a useful feedback
            self.result.put_value('ACTION_ERROR', 'Fail to execute : {}'.format(str(e)))
            # now raise an exception
            raise Exception()



    def appendAtomics(self):
        self.appendAtomic(self.parse_input, self.rollback)
        self.appendAtomic(self.check_ssh_conn, self.rollback)
        self.appendAtomic(self.action, self.rollback)


class ApacheCISExecutor(object):

    def __init__(self, apache, list_method):
        self.apache = apache
        self.list_exec = list_method
        self._final_driver_result = True
        self._extradata = {}

    def action(self):
        parse_data = {
            'Part': "Chapter " + self.apache.chapter,
            'Recommendation': {}
        }
        for key in self.list_exec:
            output = getattr(self.apache, "method_" + self.apache.chapter + "_" + str(key))()
            obj = {
                'Description': output['extrainfo'],
                'Level': output['level'],
                'Result': "Correctly configured" if output['result'] else "Misconfigured"
            }
            if not output['result']:
                obj['Remediation'] = output['remediation']
            parse_data['Recommendation'].update({output['info']: obj})
        self._extradata = parse_data

    @property
    def result(self):
        return {
            'driver_result': self._final_driver_result,
            'extradata': self._extradata
        }
