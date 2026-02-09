#bcfortiapi.fmg
#API library for Fortinet FortiManager
#Created by Benjamin Court 06-01-2026
#Last Updated: 06-02-2026

"""
bcfortiapi.fmg\n
    *Python library for communicating with Fortinet FortiManager*

Dependencies:
------------\n
    *requests, json, urllib3*

Examples:
---------\n
    *Import into Python script*
>>> import bcfortiapi

    *Initialise instance of fmgapi within script*
>>> init_variable = bcfortiapi.fmgapi(server="FMG IP or FQDN", port="FMG HTTPS Admin Port", debug=True/False)

"""

import requests
import json
from urllib3 import disable_warnings, exceptions

class fmgapi:

    """
    bcfortiapi.fmg.fmgapi\n
        *Contains functions for generating calls to the Fortinet FortiManager API*
    
    Examples:
    ---------\n
        *Login*
    >>> init_variable.login(username="Username", password="Password")
    
        *Login and return login state (bool)*
    >>> response_variable = init_variable.login(username="Username", password="Password")

        *Example GET (response returned as JSON-formatted string, can be read using json.loads)*
    >>> response_variable = init_variable.dvmdb_device(adom="ADOM name", method="get")

        *Logout*
    >>> init_variable.logout()

    """

    #----------------------------------------
    #---------- Internal Functions ----------
    #----------------------------------------

    def __init__(self, server:str="127.0.0.1", port:str="443", version:str="7.4", debug:bool=False):
        self.session = requests.Session()
        self.session.verify = False
        self.base_url = f"https://{server}:{port}/jsonrpc"
        self.db_ver = version
        self.loginstate = False
        self.payload = {}
        self.session_id = None
        self.debug = debug
        disable_warnings(exceptions.InsecureRequestWarning)
        if self.debug == True:
            self._debugger(fnct=self.__init__.__name__, mode=["std"])

    def _debugger(self, fnct=None, resp=None, mode:list=["std"]):
        if fnct is not None:
            print(f"*** bcfortiapi.fmg.fmgapi.{str(fnct)} Debug Output ***")
            print("---------------------------------------------------------------------------------")
        else:
            print(f"*** bcfortiapi.fmg.fmgapi Debug Output ***")
            print("---------------------------------------------------------------------------------")
        for i in range(len(mode)):
            if str(mode[i]) == "std":
                print(f"Session Verification: {str(self.session.verify)}")
                print(f"FMG Base URL: {str(self.base_url)}")
                print(f"FMG Configuration Database Version: {str(self.db_ver)}")
                print(f"Login State: {str(self.loginstate)}")
                print(f"Session ID: {str(self.session_id)}")
                print(f"Payload: {str(self.payload)}")
                print("")
            if (str(mode[i]) == "resp") and (resp is not None):
                print("JSON Response")
                print("")
                print(str(resp))
                print("")

    def _json_error(self, fnct=None, msg:str=None):
        err = {
            "type": "error",
            "detail": "internal",
            "function": fnct,
            "message": msg
        }
        err = json.dumps(err)
        err_json = json.loads(err)
        return err_json

    def _payload_builder(self, method:str=None, endpoint:str=None, data:dict=None, session:str=None, verbose:int=None, fields:list=[], option:str=None):
        self.payload = {
            "id": 1,
            "method": method,
            "params": [
                {
                    "url": endpoint,
                    "data": data,
                    "fields": [fields],
                    "option": option
                }
            ],
            "session": session,
            "verbose": verbose
        }
        if self.debug == True:
            self._debugger(fnct=self._payload_builder.__name__, mode=["std"])
    
    def _request(self):
        response = self.session.post(url=self.base_url, json=self.payload)
        resp_req = json.dumps(str(response.json()))
        response = str(json.loads(resp_req)).replace("'", '"').replace('None', '"None"').replace('False', 'false').replace('True','true')
        if self.debug == True:
            self._debugger(fnct=self._request.__name__, mode=["std", "resp"])
        return response
    
    #----------------------------------------------
    #---------- Authentication Functions ----------
    #----------------------------------------------

    def login(self, username:str="", password:str=""):
        """
        bcfortiapi.fmg.fmgapi.login\n
        
        API Endpoints:
        --------------\n
            */sys/login/user*
        
        Mandatory Parameters:
        ---------------------\n
            *username, password*
        
        Examples:
        ---------\n
            *Login*
        >>> init_variable.login(username="Username", password="Password")
        
            *Login and return login state (bool)*
        >>> response_variable = init_variable.login(username="Username", password="Password")

        """
        credentials = {
            "user": username,
            "passwd": password
        }
        self._payload_builder(method="exec", endpoint="/sys/login/user", data=credentials)
        response = self.session.post(url=self.base_url, json=self.payload)  
        if str(response.status_code) == "200":
            if str('session') in str(response.json()):
                self.session_id = response.json()['session']
                self.loginstate = True
            else:
                self.loginstate = False
        else:
            self.loginstate = False
        if self.debug == True:
            self._debugger(fnct=self.login.__name__, resp=response, mode=["std", "resp"])
        return self.loginstate
    
    def logout(self):
        """
        bcfortiapi.fmg.fmgapi.logout\n
        
        API Endpoints:
        --------------\n
            */sys/logout*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        Examples:
        ---------\n
        >>> init_variable.logout()

        """
        if self.loginstate == True:
            self._payload_builder(method="exec", endpoint="/sys/logout", session=self.session_id)
            response = self.session.post(url=self.base_url, json=self.payload)
            if str(response.status_code) == "200":
                self.loginstate = False
            resp_req = json.dumps(str(response.json()))
            response = str(json.loads(resp_req)).replace("'", '"').replace('None', '"None"')
            if self.debug == True:
                self._debugger(fnct=self.logout.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.logout.__name__,msg=f"Login state is {self.loginstate}")
        return response
    
    #----------------------------------------------
    #---------- System Command Functions ----------
    #----------------------------------------------

    def sys_status(self):
        """
        bcfortiapi.fmg.fmgapi.sys_status\n

        API Endpoints:
        --------------\n
            */sys/status*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        Examples:
        ---------\n
        >>> init_variable.sys_status()

        """
        if self.loginstate == True:
            self._payload_builder(method="get", endpoint="/sys/status", session=self.session_id, verbose=1)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.sys_status.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.sys_status.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def sys_hitcount(self, adom:str=None, pkg:str=None):
        """
        bcfortiapi.fmg.fmgapi.sys_hitcount\n

        API Endpoints:
        --------------\n
            */sys/hitcount*
        
        Mandatory Parameters:
        ---------------------\n
            *adom, pkg*
        
        Examples:
        ---------\n
        >>> init_variable.sys_hitcount(adom="ADOM Name", pkg="Policy Package Name")

        """
        if self.loginstate == True:
            if adom is not None:
                if pkg is not None:
                    data = {
                        "adom": adom,
                        "pkg": pkg
                    }
                    self._payload_builder(method="exec", endpoint="/sys/hitcount", session=self.session_id, verbose=1, data=data)
                    response = self._request()
                    if self.debug == True:
                        self._debugger(fnct=self.sys_hitcount.__name__, resp=response, mode=["std", "resp"])
                else:
                    response = self._json_error(fnct=self.sys_hitcount.__name__, msg=f"Package name is {pkg}")    
            else:
                response = self._json_error(fnct=self.sys_hitcount.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.sys_hitcount.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def sys_ha(self):
        """
        bcfortiapi.fmg.fmgapi.sys_ha\n

        API Endpoints:
        --------------\n
            */sys/ha/status*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        Examples:
        ---------\n
        >>> init_variable.sys_ha()

        """
        if self.loginstate == True:
            self._payload_builder(method="get", endpoint="/sys/ha/status", session=self.session_id, verbose=1)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.sys_ha.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.sys_ha.__name__, msg=f"Login state is {self.loginstate}")
        return response

    def sys_reboot(self, msg:str=None):
        """
        bcfortiapi.fmg.fmgapi.sys_reboot\n

        API Endpoints:
        --------------\n
            */sys/reboot*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        Examples:
        ---------\n
        >>> init_variable.sys_reboot(msg="Log Entry Message Text")

        """
        data = None
        if msg is not None:
            data = {
                "message": msg
            }
        if self.loginstate == True:
            self._payload_builder(method="exec", endpoint="/sys/reboot", session=self.session_id, verbose=1, data=data)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.sys_reboot.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.sys_reboot.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def sys_proxy(self, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.sys_proxy\n

        API Endpoints:
        --------------\n
            */sys/proxy/json*
        
        Mandatory Parameters:
        ---------------------\n
            *data*
        
        Examples:
        ---------\n
        >>> init_variable.sys_proxy(data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                action	[...]
                payload	{...}
                resource	[...]
                target	[...]
                timeout [...]
            }

        """
        if self.loginstate == True:
            if data is not None:
                self._payload_builder(method="exec", endpoint="/sys/proxy/json", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.sys_proxy.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.sys_proxy.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.sys_proxy.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def sys_task(self, taskid:int=None):
        """
        bcfortiapi.fmg.fmgapi.sys_task\n

        API Endpoints:
        --------------\n
            */sys/task/result*
        
        Mandatory Parameters:
        ---------------------\n
            *taskid*
        
        Examples:
        ---------\n
        >>> init_variable.sys_task(taskid=123)

        """
        if self.loginstate == True:
            if taskid is not None:
                data = {
                    "taskid": taskid
                }
                self._payload_builder(method="exec", endpoint="/sys/task/result", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.sys_task.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.sys_task.__name__, msg=f"Task ID is {taskid}")
        else:
            response = self._json_error(fnct=self.sys_task.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    #------------------------------------------------------
    #---------- Device Manager Command Functions ----------
    #------------------------------------------------------

    def dvmcmd_updatelist(self, adom:str=None, scope:list=None):
        """
        bcfortiapi.fmg.fmgapi.dvmcmd_updatelist\n

        API Endpoints:
        --------------\n
            */dvm/cmd/update/dev-list*
        
        Mandatory Parameters:
        ---------------------\n
            *adom, scope*
        
        Examples:
        ---------\n
        >>> init_variable.dvmcmd_updatelist(adom="ADOM Name", scope=[List Object])

        Scope Structure:
        ----------------\n
        >>> scope = [
                {
                    name	[...]
                    vdom	[...]
                }
            ]

        """
        if self.loginstate == True:
            if adom is not None:
                if scope is not None:
                    data = {
                        "adom": adom,
                        "flags": "create_task",
                        "update-dev-member-list": scope
                    }
                    self._payload_builder(method="exec", endpoint="/dvm/cmd/update/dev-list", session=self.session_id, verbose=1, data=data)
                    response = self._request()
                    if self.debug == True:
                        self._debugger(fnct=self.dvmcmd_updatelist.__name__, resp=response, mode=["std", "resp"])
                else:
                    response = self._json_error(fnct=self.dvmcmd_updatelist.__name__, msg=f"Device list is {scope}")
            else:
                response = self._json_error(fnct=self.dvmcmd_updatelist.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.dvmcmd_updatelist.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmcmd_updatedevice(self, adom:str=None, device:str=None):
        """
        bcfortiapi.fmg.fmgapi.dvmcmd_updatedevice\n

        API Endpoints:
        --------------\n
            */dvm/cmd/update/device*
        
        Mandatory Parameters:
        ---------------------\n
            *adom, device*
        
        Examples:
        ---------\n
        >>> init_variable.dvmcmd_updatedevice(adom="ADOM Name", device="Device Name")

        """
        if self.loginstate == True:
            if adom is not None:
                if device is not None:
                    data = {
                        "adom": adom,
                        "flags": "create_task",
                        "device": device
                    }
                    self._payload_builder(method="exec", endpoint="/dvm/cmd/update/device", session=self.session_id, verbose=1, data=data)
                    response = self._request()
                    if self.debug == True:
                        self._debugger(fnct=self.dvmcmd_updatedevice.__name__, resp=response, mode=["std", "resp"])
                else:
                    response = self._json_error(fnct=self.dvmcmd_updatedevice.__name__, msg=f"Device name is {device}")
            else:
                response = self._json_error(fnct=self.dvmcmd_updatedevice.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.dvmcmd_updatedevice.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmcmd_reloadlist(self, adom:str=None, scope:list=None):
        """
        bcfortiapi.fmg.fmgapi.dvmcmd_reloadlist\n

        API Endpoints:
        --------------\n
            */dvm/cmd/reload/dev-list*
        
        Mandatory Parameters:
        ---------------------\n
            *adom, scope*
        
        Examples:
        ---------\n
        >>> init_variable.dvmcmd_reloadlist(adom="ADOM Name", scope=[List Object])

        Scope Structure:
        ----------------\n
        >>> scope = [
                {
                    name	[...]
                    vdom	[...]
                }
            ]

        """
        if self.loginstate == True:
            if adom is not None:
                if scope is not None:
                    data = {
                        "adom": adom,
                        "flags": "create_task",
                        "from": "json",
                        "reload-dev-member-list": scope
                    }
                    self._payload_builder(method="exec", endpoint="/dvm/cmd/reload/dev-list", session=self.session_id, verbose=1, data=data)
                    response = self._request()
                    if self.debug == True:
                        self._debugger(fnct=self.dvmcmd_reloadlist.__name__, resp=response, mode=["std", "resp"])
                else:
                    response = self._json_error(fnct=self.dvmcmd_reloadlist.__name__, msg=f"Device list is {scope}")
            else:
                response = self._json_error(fnct=self.dvmcmd_reloadlist.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.dvmcmd_reloadlist.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmcmd_addlist(self, adom:str=None, scope:list=None):
        """
        bcfortiapi.fmg.fmgapi.dvmcmd_addlist\n

        API Endpoints:
        --------------\n
            */dvm/cmd/add/dev-list*
        
        Mandatory Parameters:
        ---------------------\n
            *adom, scope*
        
        Examples:
        ---------\n
        >>> init_variable.dvmcmd_addlist(adom="ADOM Name", scope=[List Object])

        Scope Structure:
        ----------------\n
        >>> scope = [
                {
                    adm_pass	[...]
                    adm_usr	[...]
                    authorization template	[...]
                    desc	[...]
                    device action	[...]
                    device blueprint	[...]
                    faz.quota	[...]
                    ip	[...]
                    meta fields	{...}
                    mgmt_mode	[...]
                    mr	[...]
                    name	[...]
                    os_type	[...]
                    os_ver	[...]
                    patch	[...]
                    platform_str	[...]
                    sn	[...]
                }
            ]

        """
        if self.loginstate == True:
            if adom is not None:
                if scope is not None:
                    data = {
                        "adom": adom,
                        "flags": "create_task",
                        "add-dev-list": scope
                    }
                    self._payload_builder(method="exec", endpoint="/dvm/cmd/add/dev-list", session=self.session_id, verbose=1, data=data)
                    response = self._request()
                    if self.debug == True:
                        self._debugger(fnct=self.dvmcmd_addlist.__name__, resp=response, mode=["std", "resp"])
                else:
                    response = self._json_error(fnct=self.dvmcmd_addlist.__name__, msg=f"Device list is {scope}")
            else:
                response = self._json_error(fnct=self.dvmcmd_addlist.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.dvmcmd_addlist.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmcmd_adddevice(self, adom:str=None, device:dict=None):
        """
        bcfortiapi.fmg.fmgapi.dvmcmd_adddevice\n

        API Endpoints:
        --------------\n
            */dvm/cmd/add/device*
        
        Mandatory Parameters:
        ---------------------\n
            *adom, device*
        
        Examples:
        ---------\n
        >>> init_variable.dvmcmd_adddevice(adom="ADOM Name", device={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> device = {
                adm_pass	[...]
                adm_usr	[...]
                authorization template	[...]
                desc	[...]
                device action	[...]
                device blueprint	[...]
                faz.quota	[...]
                ip	[...]
                meta fields	{...}
                mgmt_mode	[...]
                mr	[...]
                name	[...]
                os_type	[...]
                os_ver	[...]
                patch	[...]
                platform_str	[...]
                sn	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if device is not None:
                    data = {
                        "adom": adom,
                        "flags": "create_task",
                        "device": device
                    }
                    self._payload_builder(method="exec", endpoint="/dvm/cmd/add/device", session=self.session_id, verbose=1, data=data)
                    response = self._request()
                    if self.debug == True:
                        self._debugger(fnct=self.dvmcmd_adddevice.__name__, resp=response, mode=["std", "resp"])
                else:
                    response = self._json_error(fnct=self.dvmcmd_adddevice.__name__, msg=f"Device is {device}")
            else:
                response = self._json_error(fnct=self.dvmcmd_adddevice.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.dvmcmd_adddevice.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmcmd_changehaseq(self, adom:str=None, oldmaster:str=None, newmaster:str=None):
        """
        bcfortiapi.fmg.fmgapi.dvmcmd_changehaseq\n

        API Endpoints:
        --------------\n
            */dvm/cmd/change-ha-seq*
        
        Mandatory Parameters:
        ---------------------\n
            *adom, oldmaster, newmaster*
        
        Examples:
        ---------\n
        >>> init_variable.dvmcmd_changehaseq(adom="ADOM Name", oldmaster="Current Primary Device Name", newmaster="New Primary Device Name")

        """
        if self.loginstate == True:
            if adom is not None:
                if (oldmaster is not None) and (newmaster is not None):
                    data = {
                        "adom": adom,
                        "flags": "create_task",
                        "device": oldmaster,
                        "new_master": newmaster
                    }
                    self._payload_builder(method="exec", endpoint="/dvm/cmd/change-ha-seq", session=self.session_id, verbose=1, data=data)
                    response = self._request()
                    if self.debug == True:
                        self._debugger(fnct=self.dvmcmd_changehaseq.__name__, resp=response, mode=["std", "resp"])
                else:
                    response = self._json_error(fnct=self.dvmcmd_changehaseq.__name__, msg=f"Current Primary is {oldmaster} and New Primary is {newmaster}")
            else:
                response = self._json_error(fnct=self.dvmcmd_changehaseq.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.dvmcmd_changehaseq.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmcmd_deletelist(self, adom:str=None, scope:list=None):
        """
        bcfortiapi.fmg.fmgapi.dvmcmd_deletelist\n

        API Endpoints:
        --------------\n
            */dvm/cmd/del/dev-list*
        
        Mandatory Parameters:
        ---------------------\n
            *adom, scope*
        
        Examples:
        ---------\n
        >>> init_variable.dvmcmd_deletelist(adom="ADOM Name", scope=[List Object])

        Scope Structure:
        ----------------\n
        >>> scope = [
                {
                    name	[...]
                    vdom	[...]
                }
            ]

        """
        if self.loginstate == True:
            if adom is not None:
                if scope is not None:
                    data = {
                        "adom": adom,
                        "flags": "create_task",
                        "del-dev-member-list": scope
                    }
                    self._payload_builder(method="exec", endpoint="/dvm/cmd/del/dev-list", session=self.session_id, verbose=1, data=data)
                    response = self._request()
                    if self.debug == True:
                        self._debugger(fnct=self.dvmcmd_deletelist.__name__, resp=response, mode=["std", "resp"])
                else:
                    response = self._json_error(fnct=self.dvmcmd_deletelist.__name__, msg=f"Device list is {scope}")
            else:
                response = self._json_error(fnct=self.dvmcmd_deletelist.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.dvmcmd_deletelist.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmcmd_deletedevice(self, adom:str=None, device:str=None):
        """
        bcfortiapi.fmg.fmgapi.dvmcmd_deletedevice\n

        API Endpoints:
        --------------\n
            */dvm/cmd/del/device*
        
        Mandatory Parameters:
        ---------------------\n
            *adom, device*
        
        Examples:
        ---------\n
        >>> init_variable.dvmcmd_deletedevice(adom="ADOM Name", device="Device Name")

        """
        if self.loginstate == True:
            if adom is not None:
                if device is not None:
                    data = {
                        "adom": adom,
                        "flags": "create_task",
                        "device": device
                    }
                    self._payload_builder(method="exec", endpoint="/dvm/cmd/del/device", session=self.session_id, verbose=1, data=data)
                    response = self._request()
                    if self.debug == True:
                        self._debugger(fnct=self.dvmcmd_deletedevice.__name__, resp=response, mode=["std", "resp"])
                else:
                    response = self._json_error(fnct=self.dvmcmd_deletedevice.__name__, msg=f"Device is {device}")
            else:
                response = self._json_error(fnct=self.dvmcmd_deletedevice.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.dvmcmd_deletedevice.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmcmd_discoverdevice(self, device:dict=None):
        """
        bcfortiapi.fmg.fmgapi.dvmcmd_discoverdevice\n

        API Endpoints:
        --------------\n
            */dvm/cmd/discover/device*
        
        Mandatory Parameters:
        ---------------------\n
            *device*
        
        Examples:
        ---------\n
        >>> init_variable.dvmcmd_discoverdevice(device={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> device = {
                adm_pass	[...]
                adm_usr	[...]
                ip	[...]
            }

        """
        if self.loginstate == True:
            if device is not None:
                data = {
                    "device": device
                }
                self._payload_builder(method="exec", endpoint="/dvm/cmd/discover/device", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.dvmcmd_discoverdevice.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.dvmcmd_discoverdevice.__name__, msg=f"Device is {device}")
        else:
            response = self._json_error(fnct=self.dvmcmd_discoverdevice.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmcmd_importlist(self, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.dvmcmd_importlist\n

        API Endpoints:
        --------------\n
            */dvm/cmd/import/dev-list*
        
        Mandatory Parameters:
        ---------------------\n
            *data*
        
        Examples:
        ---------\n
        >>> init_variable.dvmcmd_importlist(data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                adom	[...]
                flags	[...]
                import-adom-members	[{
                    adom	[...]
                    dev	[...]
                    vdom	[...]
                }]
                import-adoms	[{
                    create_time	[...]
                    desc	[...]
                    flags	[...]
                    lock_override	[...]
                    log_db_retention_hours	[...]
                    log_disk_quota	[...]
                    log_disk_quota_alert_thres	[...]
                    log_disk_quota_split_ratio	[...]
                    log_file_retention_hours	[...]
                    meta fields	{...}
                    mig_mr	[...]
                    mig_os_ver	[...]
                    mode	[...]
                    mr	[...]
                    name	[...]
                    os_ver	[...]
                    primary_dns_ip4	[...]
                    primary_dns_ip6_1	[...]
                    primary_dns_ip6_2	[...]
                    primary_dns_ip6_3	[...]
                    primary_dns_ip6_4	[...]
                    restricted_prds	[...]
                    secondary_dns_ip4	[...]
                    secondary_dns_ip6_1	[...]
                    secondary_dns_ip6_2	[...]
                    secondary_dns_ip6_3	[...]
                    secondary_dns_ip6_4	[...]
                    state	[...]
                    tz	[...]
                    uuid	[...]
                    workspace_mode	[...]
                }]
                import-devices	[{
                    adm_pass	[...]
                    adm_usr	[...]
                    app_ver	[...]
                    av_ver	[...]
                    beta	[...]
                    branch_pt	[...]
                    build	[...]
                    checksum	[...]
                    conf_status	[...]
                    conn_mode	[...]
                    conn_status	[...]
                    db_status	[...]
                    desc	[...]
                    dev_status	[...]
                    eip	[...]
                    fap_cnt	[...]
                    faz.full_act	[...]
                    faz.perm	[...]
                    faz.quota	[...]
                    faz.used	[...]
                    fex_cnt	[...]
                    first_tunnel_up	[...]
                    flags	[...]
                    foslic_cpu	[...]
                    foslic_dr_site	[...]
                    foslic_inst_time	[...]
                    foslic_last_sync	[...]
                    foslic_ram	[...]
                    foslic_type	[...]
                    foslic_utm	[...]
                    fsw_cnt	[...]
                    ha.vsn	[...]
                    ha_group_id	[...]
                    ha_group_name	[...]
                    ha_mode	[...]
                    ha_slave	[{
                        conf_status	[...]
                        idx	[...]
                        name	[...]
                        prio	[...]
                        role	[...]
                        sn	[...]
                        status	[...]
                    }]
                    ha_upgrade_mode	[...]
                    hdisk_size	[...]
                    hostname	[...]
                    hw_generation	[...]
                    hw_rev_major	[...]
                    hw_rev_minor	[...]
                    hyperscale	[...]
                    ip	[...]
                    ips_ext	[...]
                    ips_ver	[...]
                    last_checked	[...]
                    last_resync	[...]
                    latitude	[...]
                    lic_flags	[...]
                    lic_region	[...]
                    location_from	[...]
                    logdisk_size	[...]
                    longitude	[...]
                    maxvdom	[...]
                    meta fields	{...}
                    mgmt_if	[...]
                    mgmt_mode	[...]
                    mgmt_uuid	[...]
                    mgt_vdom	[...]
                    module_sn	[...]
                    mr	[...]
                    name	[...]
                    nsxt_service_name	[...]
                    os_type	[...]
                    os_ver	[...]
                    patch	[...]
                    platform_str	[...]
                    prefer_img_ver	[...]
                    prio	[...]
                    private_key	[...]
                    private_key_status	[...]
                    psk	[...]
                    relver_info	[...]
                    role	[...]
                    sn	[...]
                    sov_sase_license	[...]
                    vdom	[{
                        comments	[...]
                        meta fields	{...}
                        name	[...]
                        opmode	[...]
                        rtm_prof_id	[...]
                        status	[...]
                        vdom_type	[...]
                        vpn_id	[...]
                    }]
                    version	[...]
                    vm_cpu	[...]
                    vm_cpu_limit	[...]
                    vm_lic_expire	[...]
                    vm_lic_overdue_since	[...]
                    vm_mem	[...]
                    vm_mem_limit	[...]
                    vm_payg_status	[...]
                    vm_status	[...]
                }]
                import-group-members	[{
                    adom	[...]
                    dev	[...]
                    grp	[...]
                    vdom	[...]
                }]
            }

        """
        if self.loginstate == True:
            if data is not None:
                self._payload_builder(method="exec", endpoint="/dvm/cmd/import/dev-list", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.dvmcmd_importlist.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.dvmcmd_importlist.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.dvmcmd_importlist.__name__, msg=f"Login state is {self.loginstate}")
        return response

    #--------------------------------------------------------
    #---------- Security Console Command Functions ----------
    #--------------------------------------------------------

    def seccmd_abort(self, adom:str=None):
        """
        bcfortiapi.fmg.fmgapi.seccmd_abort\n

        API Endpoints:
        --------------\n
            */securityconsole/abort*
        
        Mandatory Parameters:
        ---------------------\n
            *adom*
        
        Examples:
        ---------\n
        >>> init_variable.seccmd_abort(adom="ADOM Name")

        """
        if self.loginstate == True:
            if adom is not None:
                data = {
                    "adom": adom
                }
                self._payload_builder(method="exec", endpoint="/securityconsole/abort", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.seccmd_abort.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.seccmd_abort.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.seccmd_abort.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def seccmd_assignglobalpkg(self, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.seccmd_assignglobalpkg\n

        API Endpoints:
        --------------\n
            */securityconsole/assign/package*
        
        Mandatory Parameters:
        ---------------------\n
            *data*
        
        Examples:
        ---------\n
        >>> init_variable.seccmd_assignglobalpkg(data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                flags	[...]
                pkg	[...]
                target	[{
                    adom	[...]
                    excluded	[...]
                    pkg	[...]
                }]
            }

        """
        if self.loginstate == True:
            if data is not None:
                self._payload_builder(method="exec", endpoint="/securityconsole/assign/package", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.seccmd_assignglobalpkg.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.seccmd_assignglobalpkg.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.seccmd_assignglobalpkg.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def seccmd_cliprof_check(self, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.seccmd_cliprof_check\n

        API Endpoints:
        --------------\n
            */securityconsole/cliprof/check*
        
        Mandatory Parameters:
        ---------------------\n
            *data*
        
        Examples:
        ---------\n
        >>> init_variable.seccmd_cliprof_check(data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                adom	[...]
                cliprof	[...]
                scope	[{
                    name	[...]
                    vdom	[...]
                }]
            }
            
        """
        if self.loginstate == True:
            if data is not None:
                self._payload_builder(method="exec", endpoint="/securityconsole/cliprof/check", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.seccmd_cliprof_check.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.seccmd_cliprof_check.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.seccmd_cliprof_check.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def seccmd_importobjects(self, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.seccmd_importobjects\n

        API Endpoints:
        --------------\n
            */securityconsole/import/dev/objs*
        
        Mandatory Parameters:
        ---------------------\n
            *data*
        
        Examples:
        ---------\n
        >>> init_variable.seccmd_importobjects(data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                add_mappings	[...]
                adom	[...]
                dst_name	[...]
                dst_parent	[...]
                if_all_objs	[...]
                if_all_policy	[...]
                import_action	[...]
                name	[...]
                position	[...]
                vdom	[...]
            }
            
        """
        if self.loginstate == True:
            if data is not None:
                self._payload_builder(method="exec", endpoint="/securityconsole/import/dev/objs", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.seccmd_importobjects.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.seccmd_importobjects.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.seccmd_importobjects.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def seccmd_install(self, action:str="preview", data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.seccmd_install\n

        API Endpoints:
        --------------\n
            */securityconsole/install/device*
            */securityconsole/install/objects/v2*
            */securityconsole/install/package*
            */securityconsole/install/preview*
        
        Mandatory Parameters:
        ---------------------\n
            *data*

        Actions:
        --------\n
            *device, objects, package, preview*
        
        Examples:
        ---------\n
        >>> init_variable.seccmd_install(action="preview", data={Dictionary Object})

        Data Structure (Device):
        ------------------------\n
        >>> data = {
                adom	[...]
                dev_rev_comments	[...]
                flags	[...]
                scope	[{
                    name	[...]
                    vdom	[...]
                }]
            }

        Data Structure (Objects):
        -------------------------\n
        >>> data = {
                adom	[...]
                category	[...]
                objects	[...]
                scope	[{
                    name	[...]
                    vdom	[...]
                }]
            }

        Data Structure (Package):
        -------------------------\n
        >>> data = {
                adom	[...]
                adom_rev_comments	[...]
                adom_rev_name	[...]
                dev_rev_comments	[...]
                flags	[...]
                pkg	[...]
                scope	[{
                    name	[...]
                    vdom	[...]
                }]
            }

        Data Structure (Preview):
        -------------------------\n
        >>> data = {
                adom	[...]
                flags	[...]
                scope	[{
                    name	[...]
                    vdom	[...]
                }]
            }
            
        """
        if self.loginstate == True:
            if data is not None:
                if action == "device":
                    self._payload_builder(method="exec", endpoint="/securityconsole/install/device", session=self.session_id, verbose=1, data=data)
                elif action == "objects":
                    self._payload_builder(method="exec", endpoint="/securityconsole/install/objects/v2", session=self.session_id, verbose=1, data=data)
                elif action == "package":
                    self._payload_builder(method="exec", endpoint="/securityconsole/install/package", session=self.session_id, verbose=1, data=data)
                else:
                    self._payload_builder(method="exec", endpoint="/securityconsole/install/preview", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.seccmd_install.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.seccmd_install.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.seccmd_install.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def seccmd_pblock_clone(self, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.seccmd_pblock_clone\n

        API Endpoints:
        --------------\n
            */securityconsole/pblock/clone*
        
        Mandatory Parameters:
        ---------------------\n
            *data*
        
        Examples:
        ---------\n
        >>> init_variable.seccmd_pblock_clone(data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                adom	[...]
                dst_name	[...]
                pblock	[...]
            }
            
        """
        if self.loginstate == True:
            if data is not None:
                self._payload_builder(method="exec", endpoint="/securityconsole/pblock/clone", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.seccmd_pblock_clone.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.seccmd_pblock_clone.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.seccmd_pblock_clone.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def seccmd_preview_result(self, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.seccmd_preview_result\n

        API Endpoints:
        --------------\n
            */securityconsole/preview/result*
        
        Mandatory Parameters:
        ---------------------\n
            *data*
        
        Examples:
        ---------\n
        >>> init_variable.seccmd_preview_result(data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                adom	[...]
                scope	[{
                    name	[...]
                    vdom	[...]
                }]
            }
            
        """
        if self.loginstate == True:
            if data is not None:
                self._payload_builder(method="exec", endpoint="/securityconsole/preview/result", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.seccmd_preview_result.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.seccmd_preview_result.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.seccmd_preview_result.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def seccmd_reinstallpkg(self, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.seccmd_reinstallpkg\n

        API Endpoints:
        --------------\n
            */securityconsole/reinstall/package*
        
        Mandatory Parameters:
        ---------------------\n
            *data*
        
        Examples:
        ---------\n
        >>> init_variable.seccmd_reinstallpkg(data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                adom	[...]
                flags	[...]
                target	[{
                    pkg	[...]
                    scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                }]
            }
            
        """
        if self.loginstate == True:
            if data is not None:
                self._payload_builder(method="exec", endpoint="/securityconsole/reinstall/package", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.seccmd_reinstallpkg.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.seccmd_reinstallpkg.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.seccmd_reinstallpkg.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def seccmd_sign_certificatetemplate(self, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.seccmd_sign_certificatetemplate\n

        API Endpoints:
        --------------\n
            */securityconsole/sign/certificate/template*
        
        Mandatory Parameters:
        ---------------------\n
            *data*
        
        Examples:
        ---------\n
        >>> init_variable.seccmd_sign_certificatetemplate(data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                adom	[...]
                scope	[{
                    name	[...]
                    vdom	[...]
                }]
                template	[...]
            }
            
        """
        if self.loginstate == True:
            if data is not None:
                self._payload_builder(method="exec", endpoint="/securityconsole/sign/certificate/template", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.seccmd_sign_certificatetemplate.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.seccmd_sign_certificatetemplate.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.seccmd_sign_certificatetemplate.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def seccmd_clitemplate_preview(self, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.seccmd_clitemplate_preview\n

        API Endpoints:
        --------------\n
            */securityconsole/template/cli/preview*
        
        Mandatory Parameters:
        ---------------------\n
            *data*
        
        Examples:
        ---------\n
        >>> init_variable.seccmd_clitemplate_preview(data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                adom	[...]
                filename	[...]
                pkg	[...]
                scope	[{
                    name	[...]
                    vdom	[...]
                }]
            }
            
        """
        if self.loginstate == True:
            if data is not None:
                self._payload_builder(method="exec", endpoint="/securityconsole/template/cli/preview", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.seccmd_clitemplate_preview.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.seccmd_clitemplate_preview.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.seccmd_clitemplate_preview.__name__, msg=f"Login state is {self.loginstate}")
        return response

    #-------------------------------------------------------
    #---------- Upgrade Manager Command Functions ----------
    #-------------------------------------------------------

    def upgdmgr_upgradedevice(self, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.updgmgr_upgradedevice\n

        API Endpoints:
        --------------\n
            */um/image/upgrade/ext*
        
        Mandatory Parameters:
        ---------------------\n
            *data*
        
        Examples:
        ---------\n
        >>> init_variable.upgdmgr_upgradedevice(data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                create_task	[...]
                device	[{
                    name	[...]
                    vdom	[...]
                }]
                flags	[...]
                image	[...]
                schedule_time	[...]
            }
            
        """
        if self.loginstate == True:
            if data is not None:
                self._payload_builder(method="exec", endpoint="/um/image/upgrade/ext", session=self.session_id, verbose=1, data=data)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.upgdmgr_upgradedevice.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.upgdmgr_upgradedevice.__name__, msg=f"Data is {data}")
        else:
            response = self._json_error(fnct=self.upgdmgr_upgradedevice.__name__, msg=f"Login state is {self.loginstate}")
        return response

    #-----------------------------------------------
    #---------- Database Module Functions ----------
    #-----------------------------------------------

    def dvmdb_device(self, adom:str=None, method:str="get", data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.dvmdb_device\n

        API Endpoints:
        --------------\n
            */dvmdb/device*
            */dvmdb/adom/{adom}/device*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, set, update*
        
        Examples:
        ---------\n
        >>> init_variable.dvmdb_device(adom="ADOM Name", method="HTTP Method", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                adm_pass	[...]
                adm_usr	[...]
                app_ver	[...]
                av_ver	[...]
                beta	[...]
                branch_pt	[...]
                build	[...]
                checksum	[...]
                conf_status	[...]
                conn_mode	[...]
                conn_status	[...]
                db_status	[...]
                desc	[...]
                dev_status	[...]
                eip	[...]
                fap_cnt	[...]
                faz.full_act	[...]
                faz.perm	[...]
                faz.quota	[...]
                faz.used	[...]
                fex_cnt	[...]
                first_tunnel_up	[...]
                flags	[...]
                foslic_cpu	[...]
                foslic_dr_site	[...]
                foslic_inst_time	[...]
                foslic_last_sync	[...]
                foslic_ram	[...]
                foslic_type	[...]
                foslic_utm	[...]
                fsw_cnt	[...]
                ha.vsn	[...]
                ha_group_id	[...]
                ha_group_name	[...]
                ha_mode	[...]
                ha_upgrade_mode	[...]
                hdisk_size	[...]
                hostname	[...]
                hw_generation	[...]
                hw_rev_major	[...]
                hw_rev_minor	[...]
                hyperscale	[...]
                ip	[...]
                ips_ext	[...]
                ips_ver	[...]
                last_checked	[...]
                last_resync	[...]
                latitude	[...]
                lic_flags	[...]
                lic_region	[...]
                location_from	[...]
                logdisk_size	[...]
                longitude	[...]
                maxvdom	[...]
                meta fields	{
                    description		[...]
                }
                mgmt_if	[...]
                mgmt_mode	[...]
                mgmt_uuid	[...]
                mgt_vdom	[...]
                module_sn	[...]
                mr	[...]
                name	[...]
                nsxt_service_name	[...]
                os_type	[...]
                os_ver	[...]
                patch	[...]
                platform_str	[...]
                prefer_img_ver	[...]
                prio	[...]
                private_key	[...]
                private_key_status	[...]
                psk	[...]
                relver_info	[...]
                role	[...]
                sn	[...]
                sov_sase_license	[...]
                vdom	[{
                    comments	[...]
                    meta fields	{...}
                    name	[...]
                    opmode	[...]
                    rtm_prof_id	[...]
                    status	[...]
                    vdom_type	[...]
                    vpn_id	[...]
                }]
                version	[...]
                vm_cpu	[...]
                vm_cpu_limit	[...]
                vm_lic_expire	[...]
                vm_lic_overdue_since	[...]
                vm_mem	[...]
                vm_mem_limit	[...]
                vm_payg_status	[...]
                vm_status   [...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                self._payload_builder(method=method, endpoint=f"/dvmdb/adom/{adom}/device", session=self.session_id, verbose=1, data=data)
            else:
                self._payload_builder(method=method, endpoint="/dvmdb/device", session=self.session_id, verbose=1, data=data)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.dvmdb_device.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.dvmdb_device.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmdb_device_replace(self, adom:str=None, device:str=None, new_serial:str=None):
        """
        bcfortiapi.fmg.fmgapi.dvmdb_device_replace\n

        API Endpoints:
        --------------\n
            */dvmdb/adom/{adom}/device/replace/sn/{device}*
        
        Mandatory Parameters:
        ---------------------\n
            *adom, device, new_serial*
        
        Examples:
        ---------\n
        >>> init_variable.dvmdb_device_replace(adom="ADOM Name", device="Device Name", new_serial="Replacement Serial Number")

        """
        if self.loginstate == True:
            if adom is not None:
                if device is not None:
                    if new_serial is not None:
                        data = {
                            "sn": new_serial
                        }
                        self._payload_builder(method="exec", endpoint=f"/dvmdb/adom/{adom}/device/replace/sn/{device}", session=self.session_id, verbose=1, data=data)
                        response = self._request()
                        if self.debug == True:
                            self._debugger(fnct=self.dvmdb_device_replace.__name__, resp=response, mode=["std", "resp"])
                    else:
                        response = self._json_error(fnct=self.dvmdb_device_replace.__name__, msg=f"New serial number is {new_serial}")
                else:
                    response = self._json_error(fnct=self.dvmdb_device_replace.__name__, msg=f"Device name is {device}")
            else:
                response = self._json_error(fnct=self.dvmdb_device_replace.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.dvmdb_device_replace.__name__, msg=f"Login state is {self.loginstate}")
        return response
        
    def dvmdb_adom(self, adom:str=None, method:str="get", data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.dvmdb_adom\n

        API Endpoints:
        --------------\n
            */dvmdb/adom*
            */dvmdb/adom/{adom}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update*
        
        Examples:
        ---------\n
        >>> init_variable.dvmdb_adom(adom="ADOM Name", method="HTTP Method", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                create_time	[...]
                desc	[...]
                flags	[...]
                lock_override	[...]
                log_db_retention_hours	[...]
                log_disk_quota	[...]
                log_disk_quota_alert_thres	[...]
                log_disk_quota_split_ratio	[...]
                log_file_retention_hours	[...]
                meta fields	{
                    description:	
                }
                mig_mr	[...]
                mig_os_ver	[...]
                mode	[...]
                mr	[...]
                name	[...]
                os_ver	[...]
                primary_dns_ip4	[...]
                primary_dns_ip6_1	[...]
                primary_dns_ip6_2	[...]
                primary_dns_ip6_3	[...]
                primary_dns_ip6_4	[...]
                restricted_prds	[...]
                secondary_dns_ip4	[...]
                secondary_dns_ip6_1	[...]
                secondary_dns_ip6_2	[...]
                secondary_dns_ip6_3	[...]
                secondary_dns_ip6_4	[...]
                state	[...]
                tz	[...]
                uuid	[...]
                workspace_mode  [...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                self._payload_builder(method=method, endpoint=f"/dvmdb/adom/{adom}", session=self.session_id, verbose=1, data=data)
            else:
                self._payload_builder(method=method, endpoint="/dvmdb/adom", session=self.session_id, verbose=1, data=data)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.dvmdb_adom.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.dvmdb_adom.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmdb_script(self, adom:str=None, method:str="get", data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.dvmdb_script\n

        API Endpoints:
        --------------\n
            */dvmdb/script*
            */dvmdb/adom/{adom}/script*
            */dvmdb/script/execute*
            */dvmdb/adom/{adom}/script/execute*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, exec*
        
        Examples:
        ---------\n
        >>> init_variable.dvmdb_script(adom="ADOM Name", method="HTTP Method", data={Dictionary Object})

        Data Structure (Script):
        ------------------------\n
        >>> data = {
                content	[...]
                desc	[...]
                filter_build	[...]
                filter_device	[...]
                filter_hostname	[...]
                filter_ostype	[...]
                filter_osver	[...]
                filter_platform	[...]
                filter_serial	[...]
                modification_time	[...]
                name	[...]
                script_schedule	[{
                    datetime	[...]
                    day_of_week	[...]
                    device	[...]
                    name	[...]
                    run_on_db	[...]
                    type	[...]
                }]
                target	[...]
                type    [...]
            }
        
        Data Structure (Script Execute):
        --------------------------------\n
        >>> data = {
                adom	[...]
                package	[...]
                pblock	[...]
                scope	[{
                    name	[...]
                    vdom	[...]
                }]
                script	[...]
            }

        """
        if self.loginstate == True:
            if method == "exec":
                if adom is not None:
                    self._payload_builder(method=method, endpoint=f"/dvmdb/adom/{adom}/script/execute", session=self.session_id, verbose=1, data=data)
                else:
                    self._payload_builder(method=method, endpoint="/dvmdb/script/execute", session=self.session_id, verbose=1, data=data)
            else:
                if adom is not None:
                    self._payload_builder(method=method, endpoint=f"/dvmdb/adom/{adom}/script", session=self.session_id, verbose=1, data=data)
                else:
                    self._payload_builder(method=method, endpoint="/dvmdb/script", session=self.session_id, verbose=1, data=data)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.dvmdb_script.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.dvmdb_script.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmdb_script_log_output(self, adom:str=None, device:str=None, taskid:str=None):
        """
        bcfortiapi.fmg.fmgapi.dvmdb_script_log_output\n

        API Endpoints:
        --------------\n
            */dvmdb/global/script/log/output/logid/{taskid}*
            */dvmdb/adom/{adom}/script/log/output/logid/{taskid}*
            */dvmdb/adom/{adom}/script/log/output/device/{device}/logid/{taskid}*
        
        Mandatory Parameters:
        ---------------------\n
            *taskid*
        
        Examples:
        ---------\n
        >>> init_variable.dvmdb_script_log_output(adom="ADOM Name", device"Device Name", taskid="Task ID")

        """
        if self.loginstate == True:
            if taskid is not None:
                if adom is not None:
                    if device is not None:
                        self._payload_builder(method="get", endpoint=f"/dvmdb/adom/{adom}/script/log/output/device/{device}/logid/{taskid}", session=self.session_id, verbose=1)
                    else:
                        self._payload_builder(method="get", endpoint=f"/dvmdb/adom/{adom}/script/log/output/logid/{taskid}", session=self.session_id, verbose=1)
                else:
                    self._payload_builder(method="get", endpoint=f"/dvmdb/global/script/log/output/logid/{taskid}", session=self.session_id, verbose=1)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.dvmdb_script_log_output.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.dvmdb_script_log_output.__name__, msg=f"Task ID is {taskid}")
        else:
            response = self._json_error(fnct=self.dvmdb_script_log_output.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmdb_script_log_summary(self, adom:str=None, device:str=None):
        """
        bcfortiapi.fmg.fmgapi.dvmdb_script_log_summary\n

        API Endpoints:
        --------------\n
            */dvmdb/global/script/log/summary*
            */dvmdb/script/log/summary/device/{device}*
            */dvmdb/adom/{adom}/script/log/summary*
            */dvmdb/adom/{adom}/script/log/summary/device/{device}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        Examples:
        ---------\n
        >>> init_variable.dvmdb_script_log_summary(adom="ADOM Name", device="Device Name")

        """
        if self.loginstate == True:
            if adom is not None:
                if device is not None:
                    self._payload_builder(method="get", endpoint=f"/dvmdb/adom/{adom}/script/log/summary/device/{device}", session=self.session_id, verbose=1)
                else:
                    self._payload_builder(method="get", endpoint=f"/dvmdb/adom/{adom}/script/log/summary", session=self.session_id, verbose=1)
            else:
                if device is not None:
                    self._payload_builder(method="get", endpoint=f"/dvmdb/script/log/summary/device/{device}", session=self.session_id, verbose=1)
                else:
                    self._payload_builder(method="get", endpoint=f"/dvmdb/global/script/log/summary", session=self.session_id, verbose=1)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.dvmdb_script_log_summary.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.dvmdb_script_log_summary.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def dvmdb_workspace(self, adom:str=None, action:str="info"):
        """
        bcfortiapi.fmg.fmgapi.dvmdb_workspace\n

        API Endpoints:
        --------------\n
            */dvmdb/global/workspace/lockinfo*
            */dvmdb/adom/{adom}/workspace/lockinfo*
            */dvmdb/global/workspace/lock*
            */dvmdb/adom/{adom}/workspace/lock*
            */dvmdb/global/workspace/unlock*
            */dvmdb/adom/{adom}/workspace/unlock*
            */dvmdb/global/workspace/commit*
            */dvmdb/adom/{adom}/workspace/commit*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        Actions:
        --------\n
            *info, lock, unlock, commit*
        
        Examples:
        ---------\n
        >>> init_variable.dvmdb_workspace(adom="ADOM Name", action="info")

        """
        if self.loginstate == True:
            if action == "info":
                method = "get"
                if adom is not None:
                    self._payload_builder(method=method, endpoint=f"/dvmdb/adom/{adom}/workspace/lockinfo", session=self.session_id, verbose=1)
                else:
                    self._payload_builder(method=method, endpoint="/dvmdb/global/workspace/lockinfo", session=self.session_id, verbose=1)
            elif action == "lock":
                method = "exec"
                if adom is not None:
                    self._payload_builder(method=method, endpoint=f"/dvmdb/adom/{adom}/workspace/lock", session=self.session_id, verbose=1)
                else:
                    self._payload_builder(method=method, endpoint="/dvmdb/global/workspace/lock", session=self.session_id, verbose=1)
            elif action == "unlock":
                method = "exec"
                if adom is not None:
                    self._payload_builder(method=method, endpoint=f"/dvmdb/adom/{adom}/workspace/unlock", session=self.session_id, verbose=1)
                else:
                    self._payload_builder(method=method, endpoint="/dvmdb/global/workspace/unlock", session=self.session_id, verbose=1)
            elif action == "commit":
                method = "exec"
                if adom is not None:
                    self._payload_builder(method=method, endpoint=f"/dvmdb/adom/{adom}/workspace/commit", session=self.session_id, verbose=1)
                else:
                    self._payload_builder(method=method, endpoint="/dvmdb/global/workspace/commit", session=self.session_id, verbose=1)
            else:
                method = "get"
                if adom is not None:
                    self._payload_builder(method=method, endpoint=f"/dvmdb/adom/{adom}/workspace/lockinfo", session=self.session_id, verbose=1)
                else:
                    self._payload_builder(method=method, endpoint="/dvmdb/global/workspace/lockinfo", session=self.session_id, verbose=1)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.dvmdb_workspace.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.dvmdb_workspace.__name__, msg=f"Login state is {self.loginstate}")
        return response
            
    def dvmdb_revision(self, adom:str=None, method:str="get", revision:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.dvmdb_revision\n

        API Endpoints:
        --------------\n
            */dvmdb/revision*
            */dvmdb/revision/{revision}*
            */dvmdb/global/revision*
            */dvmdb/global/revision/{revision}*
            */dvmdb/adom/{adom}/revision*
            */dvmdb/adom/{adom}/revision/{revision}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Examples:
        ---------\n
        >>> init_variable.dvmdb_revision(adom="ADOM Name", method="HTTP Method", revision="Revision Name", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                created_by	[...]
                created_time	[...]
                desc	[...]
                locked	[...]
                name	[...]
                version	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if adom == "global":
                    if revision is not None:
                        self._payload_builder(method=method, endpoint=f"/dvmdb/global/revision/{revision}", session=self.session_id, verbose=1, data=data)
                    else:
                        self._payload_builder(method=method, endpoint=f"/dvmdb/global/revision", session=self.session_id, verbose=1, data=data)
                else:
                    if revision is not None:
                        self._payload_builder(method=method, endpoint=f"/dvmdb/adom/{adom}/revision/{revision}", session=self.session_id, verbose=1, data=data)
                    else:
                        self._payload_builder(method=method, endpoint=f"/dvmdb/adom/{adom}/revision", session=self.session_id, verbose=1, data=data)
            else:
                if revision is not None:
                    self._payload_builder(method=method, endpoint=f"/dvmdb/revision/{revision}", session=self.session_id, verbose=1, data=data)
                else:
                    self._payload_builder(method=method, endpoint=f"/dvmdb/revision", session=self.session_id, verbose=1, data=data)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.dvmdb_revision.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.dvmdb_revision.__name__, msg=f"Login state is {self.loginstate}")
        return response

    def dvmdb_task(self, taskid:str=None):
        """
        bcfortiapi.fmg.fmgapi.dvmdb_task\n

        API Endpoints:
        --------------\n
            */task/task*
            */task/task/{taskid}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        Examples:
        ---------\n
        >>> init_variable.dvmdb_task(taskid="123")

        """
        if self.loginstate == True:
            if taskid is not None:
                self._payload_builder(method="get", endpoint=f"/task/task/{taskid}", session=self.session_id, verbose=1)
            else:
                self._payload_builder(method="get", endpoint=f"/task/task", session=self.session_id, verbose=1)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.dvmdb_task.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.dvmdb_task.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    #------------------------------------------------------
    #---------- Configuration Database Functions ----------
    #------------------------------------------------------

    def confdb_pblock(self, adom:str=None, method:str="get", pblock:str=None, data:dict=None, fields:list=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_pblock\n

        API Endpoints:
        --------------\n
            */pm/pblock/adom/{adom}*
            */pm/pblock/adom/{adom}/{name}*
        
        Mandatory Parameters:
        ---------------------\n
            *adom*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete*
        
        Examples:
        ---------\n
        >>> init_variable.confdb_pblock(adom="ADOM Name", method="HTTP Method", pblock="Policy Block Name", data={Dictionary Object}, fields=[List Object])

        Data Structure:
        ---------------\n
        >>> data = {
                name	[...]
                oid	[...]
                package settings	{
                    central-nat	[...]
                    consolidated-firewall-mode	[...]
                    fwpolicy-implicit-log	[...]
                    fwpolicy6-implicit-log	[...]
                    inspection-mode	[...]
                    ngfw-mode	[...]
                    policy-offload-level	[...]
                    ssl-ssh-profile	[...]
                }
                type	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if pblock is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/pblock/adom/{adom}/{pblock}", session=self.session_id, verbose=1, data=data, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/pblock/adom/{adom}", session=self.session_id, verbose=1, data=data, fields=fields)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.confdb_pblock.__name__, resp=response, mode=["std", "resp"])
            else:
                response = self._json_error(fnct=self.confdb_pblock.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.confdb_pblock.__name__, msg=f"Login state is {self.loginstate}")
        return response

    def confdb_pkg(self, adom:str=None, method:str="get", pkg:str=None, data:dict=None, fields:list=None, set_scope:bool=False):
        """
        bcfortiapi.fmg.fmgapi.confdb_pkg\n

        API Endpoints:
        --------------\n
            */pm/pkg/global*
            */pm/pkg/global/{name}*
            */pm/pkg/global/{name}/scope member*
            */pm/pkg/adom/{adom}*
            */pm/pkg/adom/{adom}/{name}*
            */pm/pkg/adom/{adom}/{name}/scope member*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, unset, update, delete*
        
        Fields:
        --------\n
            *name, obj ver, oid, scope member, type*
        
        Examples:
        ---------\n
        >>> init_variable.confdb_pkg(adom="ADOM Name", method="HTTP Method", pkg="Policy Package Name", data={Dictionary Object}, fields=[List Object], set_scope=True/False)

        Data Structure:
        ---------------\n
        >>> data = {
                name	[...]
                obj ver	[...]
                oid	[...]
                package settings	{
                    central-nat	[...]
                    consolidated-firewall-mode	[...]
                    fwpolicy-implicit-log	[...]
                    fwpolicy6-implicit-log	[...]
                    inspection-mode	[...]
                    ngfw-mode	[...]
                    policy-offload-level	[...]
                    ssl-ssh-profile	[...]
                }
                scope member	[{
                    name	[...]
                    vdom	[...]
                }]
                subobj	[...]
                type	[...]
            }
        
        Data Structure (set_scope=True):
        --------------------------------\n
        >>> data = {
                name	[...]
                vdom	[...]
            }

        """
        if self.loginstate == True:
            if set_scope == False:
                if adom is not None:
                    if pkg is not None:
                        self._payload_builder(method=method, endpoint=f"/pm/pkg/adom/{adom}/{pkg}", session=self.session_id, verbose=1, data=data, fields=fields)
                    else:
                        self._payload_builder(method=method, endpoint=f"/pm/pkg/adom/{adom}", session=self.session_id, verbose=1, data=data, fields=fields)
                else:
                    if pkg is not None:
                        self._payload_builder(method=method, endpoint=f"/pm/pkg/global/{pkg}", session=self.session_id, verbose=1, data=data, fields=fields)
                    else:
                        self._payload_builder(method=method, endpoint=f"/pm/pkg/global", session=self.session_id, verbose=1, data=data, fields=fields)
                response = self._request()
                if self.debug == True:
                    self._debugger(fnct=self.confdb_pkg.__name__, resp=response, mode=["std", "resp"])
            else:
                if pkg is not None:
                    if adom is not None:
                        self._payload_builder(method=method, endpoint=f"/pm/pkg/adom/{adom}/{pkg}/scope member", session=self.session_id, verbose=1, data=data, fields=fields)
                    else:
                        self._payload_builder(method=method, endpoint=f"/pm/pkg/global/{pkg}/scope member", session=self.session_id, verbose=1, data=data, fields=fields)
                    response = self._request()
                else:
                    response = self._json_error(fnct=self.confdb_pkg.__name__, msg=f"Policy package name is {pkg}")
        else:
            response = self._json_error(fnct=self.confdb_pkg.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_pkgsettings(self, adom:str=None, pkg:str=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_pkgsettings\n

        API Endpoints:
        --------------\n
            */pm/config/adom/{adom}/pkg/{pkg}/policy/package/settings*
        
        Mandatory Parameters:
        ---------------------\n
            *adom, pkg*

        Examples:
        ---------\n
        >>> init_variable.confdb_pkgsettings(adom="ADOM Name", pkg="Policy Package Name")

        """
        if self.loginstate == True:
            if adom is not None:
                if pkg is not None:
                    self._payload_builder(method="get", endpoint=f"/pm/config/adom/{adom}/pkg/{pkg}/policy/package/settings", session=self.session_id, verbose=1)
                    response = self._request()
                    if self.debug == True:
                        self._debugger(fnct=self.confdb_pkgsettings.__name__, resp=response, mode=["std", "resp"])
                else:
                    response = self._json_error(fnct=self.confdb_pkgsettings.__name__, msg=f"Policy package name is {pkg}")
            else:
                response = self._json_error(fnct=self.confdb_pkgsettings.__name__, msg=f"ADOM is {adom}")
        else:
            response = self._json_error(fnct=self.confdb_pkgsettings.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_adom_options(self, adom:str=None, method:str="get", data:dict=None, option:str=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_adom_options\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/adom/options*
            */pm/config/adom/{adom}/obj/adom/options*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, set, update*
        
        Options:
        --------\n
            *scope member, chksum, datasrc*
        
        Examples:
        ---------\n
        >>> init_variable.confdb_adom_options(adom="ADOM Name", method="HTTP Method", data={Dictionary Object}, option="Option")

        Data Structure:
        ---------------\n
        >>> data = {
                assign_excluded	[...]
                assign_name	[...]
                specify_assign_pkg_list	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/adom/options", session=self.session_id, verbose=1, data=data, option=option)
            else:
                self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/adom/options", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_adom_options.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_adom_options.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_av_profile(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_av_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/antivirus/profile*
            */pm/config/global/obj/antivirus/profile/{profile}*
            */pm/config/adom/{adom}/obj/antivirus/profile*
            */pm/config/adom/{adom}/obj/antivirus/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *analytics-accept-filetype, analytics-db, analytics-ignore-filetype, av-virus-log, comment, ems-threat-feed, extended-log, external-blocklist, external-blocklist-enable-all, feature-set, fortindr-error-action, fortindr-timeout-action, fortisandbox-error-action, fortisandbox-max-upload, fortisandbox-mode, fortisandbox-timeout-action, mobile-malware-db, name, outbreak-prevention-archive-scan, replacemsg-group, scan-mode*
        
        Examples:
        ---------\n
        >>> init_variable.confdb_av_profile(adom="ADOM Name", profile="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                analytics-accept-filetype	[...]
                analytics-db	[...]
                analytics-ignore-filetype	[...]
                av-virus-log	[...]
                cifs	{
                    archive-block	[...]
                    archive-log	[...]
                    av-scan	[...]
                    emulator	[...]
                    external-blocklist	[...]
                    fortindr	[...]
                    fortisandbox	[...]
                    outbreak-prevention	[...]
                    quarantine	[...]
                }
                comment	[...]
                content-disarm	{
                    analytics-suspicious	[...]
                    cover-page	[...]
                    detect-only	[...]
                    error-action	[...]
                    office-action	[...]
                    office-dde	[...]
                    office-embed	[...]
                    office-hylink	[...]
                    office-linked	[...]
                    office-macro	[...]
                    original-file-destination	[...]
                    pdf-act-form	[...]
                    pdf-act-gotor	[...]
                    pdf-act-java	[...]
                    pdf-act-launch	[...]
                    pdf-act-movie	[...]
                    pdf-act-sound	[...]
                    pdf-embedfile	[...]
                    pdf-hyperlink	[...]
                    pdf-javacode	[...]
                }
                ems-threat-feed	[...]
                extended-log	[...]
                external-blocklist	[...]
                external-blocklist-enable-all	[...]
                feature-set	[...]
                fortindr-error-action	[...]
                fortindr-timeout-action	[...]
                fortisandbox-error-action	[...]
                fortisandbox-max-upload	[...]
                fortisandbox-mode	[...]
                fortisandbox-timeout-action	[...]
                ftp	{
                    archive-block	[...]
                    archive-log	[...]
                    av-scan	[...]
                    emulator	[...]
                    external-blocklist	[...]
                    fortindr	[...]
                    fortisandbox	[...]
                    outbreak-prevention	[...]
                    quarantine	[...]
                }
                http	{
                    archive-block	[...]
                    archive-log	[...]
                    av-scan	[...]
                    content-disarm	[...]
                    emulator	[...]
                    external-blocklist	[...]
                    fortindr	[...]
                    fortisandbox	[...]
                    outbreak-prevention	[...]
                    quarantine	[...]
                }
                imap	{
                    archive-block	[...]
                    archive-log	[...]
                    av-scan	[...]
                    content-disarm	[...]
                    emulator	[...]
                    executables	[...]
                    external-blocklist	[...]
                    fortindr	[...]
                    fortisandbox	[...]
                    outbreak-prevention	[...]
                    quarantine	[...]
                }
                mapi	{
                    archive-block	[...]
                    archive-log	[...]
                    av-scan	[...]
                    emulator	[...]
                    executables	[...]
                    external-blocklist	[...]
                    fortindr	[...]
                    fortisandbox	[...]
                    outbreak-prevention	[...]
                    quarantine	[...]
                }
                mobile-malware-db	[...]
                nac-quar	{
                    expiry	[...]
                    infected	[...]
                    log	[...]
                }
                name	[...]
                nntp	{
                    archive-block	[...]
                    archive-log	[...]
                    av-scan	[...]
                    emulator	[...]
                    external-blocklist	[...]
                    fortindr	[...]
                    fortisandbox	[...]
                    outbreak-prevention	[...]
                    quarantine	[...]
                }
                outbreak-prevention-archive-scan	[...]
                pop3	{
                    archive-block	[...]
                    archive-log	[...]
                    av-scan	[...]
                    content-disarm	[...]
                    emulator	[...]
                    executables	[...]
                    external-blocklist	[...]
                    fortindr	[...]
                    fortisandbox	[...]
                    outbreak-prevention	[...]
                    quarantine	[...]
                }
                replacemsg-group	[...]
                scan-mode	[...]
                smtp	{
                    archive-block	[...]
                    archive-log	[...]
                    av-scan	[...]
                    content-disarm	[...]
                    emulator	[...]
                    executables	[...]
                    external-blocklist	[...]
                    fortindr	[...]
                    fortisandbox	[...]
                    outbreak-prevention	[...]
                    quarantine	[...]
                }
                ssh	{
                    archive-block	[...]
                    archive-log	[...]
                    av-scan	[...]
                    emulator	[...]
                    external-blocklist	[...]
                    fortindr	[...]
                    fortisandbox	[...]
                    outbreak-prevention	[...]
                    quarantine	[...]
                }
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/antivirus/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/antivirus/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/antivirus/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/antivirus/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_av_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_av_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_application_profile(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_application_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/application/list*
            */pm/config/global/obj/application/list/{list}*
            */pm/config/adom/{adom}/obj/application/list*
            */pm/config/adom/{adom}/obj/application/list/{list}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *app-replacemsg, comment, control-default-network-services, deep-app-inspection, enforce-default-app-port, extended-log, force-inclusion-ssl-di-sigs, name, options, other-application-action, other-application-log, p2p-block-list, replacemsg-group, unknown-application-action, unknown-application-log*
        
        Examples:
        ---------\n
        >>> init_variable.confdb_application_profile(adom="ADOM Name", profile="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                app-replacemsg	[...]
                comment	[...]
                control-default-network-services	[...]
                deep-app-inspection	[...]
                default-network-services	[{
                    id	[...]
                    port	[...]
                    services	[...]
                    violation-action	[...]
                }]
                enforce-default-app-port	[...]
                entries	[{
                    action	[...]
                    application	[...]
                    behavior	[...]
                    category	[...]
                    exclusion	[...]
                    id	[...]
                    log	[...]
                    log-packet	[...]
                    parameters	[{
                        id	[...]
                        members	[...]
                    }]
                    per-ip-shaper	[...]
                    popularity	[...]
                    protocols	[...]
                    quarantine	[...]
                    quarantine-expiry	[...]
                    quarantine-log	[...]
                    rate-count	[...]
                    rate-duration	[...]
                    rate-mode	[...]
                    rate-track	[...]
                    risk	[...]
                    session-ttl	[...]
                    shaper	[...]
                    shaper-reverse	[...]
                    technology	[...]
                    vendor	[...]
                }]
                extended-log	[...]
                force-inclusion-ssl-di-sigs	[...]
                name	[...]
                options	[...]
                other-application-action	[...]
                other-application-log	[...]
                p2p-block-list	[...]
                replacemsg-group	[...]
                unknown-application-action	[...]
                unknown-application-log	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/application/list/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/application/list", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/application/list/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/application/list", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_application_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_application_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_application_category(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_application_category\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/application/categories*
            */pm/config/global/obj/application/categories/{category}*
            */pm/config/adom/{adom}/obj/application/categories*
            */pm/config/adom/{adom}/obj/application/categories/{category}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *id*

        Examples:
        ---------\n
        >>> init_variable.confdb_application_category(adom="ADOM Name", name="Category ID", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                id	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/application/categories/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/application/categories", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/application/categories/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/application/categories", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_application_category.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_application_category.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_application_custom(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_application_custom\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/application/custom*
            */pm/config/global/obj/application/custom/{application}*
            */pm/config/adom/{adom}/obj/application/custom*
            */pm/config/adom/{adom}/obj/application/custom/{application}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *behavior, category, comment, id, name, protocol, signature, tag, technology, vendor*

        Examples:
        ---------\n
        >>> init_variable.confdb_application_custom(adom="ADOM Name", name="Application Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                behavior	[...]
                category	[...]
                comment	[...]
                id	[...]
                name	[...]
                protocol	[...]
                signature	[...]
                tag	[...]
                technology	[...]
                vendor	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/application/custom/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/application/custom", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/application/custom/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/application/custom", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_application_custom.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_application_custom.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_application_grp(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_application_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/application/group*
            */pm/config/global/obj/application/group/{group}*
            */pm/config/adom/{adom}/obj/application/group*
            */pm/config/adom/{adom}/obj/application/group/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *application, behavior, category, comment, name, popularity, protocols, risk, technology, type, vendor*

        Examples:
        ---------\n
        >>> init_variable.confdb_application_grp(adom="ADOM Name", name="Application Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                application	[...]
                behavior	[...]
                category	[...]
                comment	[...]
                name	[...]
                popularity	[...]
                protocols	[...]
                risk	[...]
                technology	[...]
                type	[...]
                vendor	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/application/group/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/application/group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/application/group/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/application/group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_application_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_application_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dnsfilter_profile(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dnsfilter_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dnsfilter/profile*
            */pm/config/global/obj/dnsfilter/profile/{profile}*
            */pm/config/adom/{adom}/obj/dnsfilter/profile*
            */pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *block-action, block-botnet, comment, external-ip-blocklist, log-all-domain, name, redirect-portal, redirect-portal6, safe-search, sdns-domain-log, sdns-ftgd-err-log, strip-ech, transparent-dns-database, youtube-restrict*

        Examples:
        ---------\n
        >>> init_variable.confdb_dnsfilter_profile(adom="ADOM Name", profile="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                block-action	[...]
                block-botnet	[...]
                comment	[...]
                dns-translation	[{
                    addr-type	[...]
                    dst	[...]
                    dst6	[...]
                    id	[...]
                    netmask	[...]
                    prefix	[...]
                    src	[...]
                    src6	[...]
                    status	[...]
                }]
                domain-filter	{
                    domain-filter-table	[...]
                }
                external-ip-blocklist	[...]
                ftgd-dns	{
                    filters	[{
                        action	[...]
                        category	[...]
                        id	[...]
                        log	[...]
                    }]
                    options	[...]
                }
                log-all-domain	[...]
                name	[...]
                redirect-portal	[...]
                redirect-portal6	[...]
                safe-search	[...]
                sdns-domain-log	[...]
                sdns-ftgd-err-log	[...]
                strip-ech	[...]
                transparent-dns-database	[...]
                youtube-restrict	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dnsfilter/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dnsfilter/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dnsfilter/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dnsfilter_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dnsfilter_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dnsfilter_domainfilter(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dnsfilter_domainfilter\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dnsfilter/domain-filter*
            */pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}*
            */pm/config/adom/{adom}/obj/dnsfilter/domain-filter*
            */pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, id, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_dnsfilter_domainfilter(adom="ADOM Name", profile="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                entries	[{
                    action	[...]
                    domain	[...]
                    id	[...]
                    status	[...]
                    type	[...]
                }]
                id	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dnsfilter/domain-filter", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dnsfilter/domain-filter/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dnsfilter/domain-filter", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dnsfilter_domainfilter.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dnsfilter_domainfilter.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_emailfilter_profile(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_emailfilter_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/emailfilter/profile*
            */pm/config/global/obj/emailfilter/profile/{profile}*
            */pm/config/adom/{adom}/obj/emailfilter/profile*
            */pm/config/adom/{adom}/obj/emailfilter/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, external, feature-set, name, options, replacemsg-group, spam-bal-table, spam-bword-table, spam-bword-threshold, spam-filtering, spam-iptrust-table, spam-log, spam-log-fortiguard-response, spam-mheader-table, spam-rbl-table*

        Examples:
        ---------\n
        >>> init_variable.confdb_emailfilter_profile(adom="ADOM Name", profile="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                external	[...]
                feature-set	[...]
                gmail	{
                    log-all	[...]
                }
                imap	{
                    action	[...]
                    log-all	[...]
                    tag-msg	[...]
                    tag-type	[...]
                }
                mapi	{
                    action	[...]
                    log-all	[...]
                }
                msn-hotmail	{
                    log-all	[...]
                }
                name	[...]
                options	[...]
                pop3	{
                    action	[...]
                    log-all	[...]
                    tag-msg	[...]
                    tag-type	[...]
                }
                replacemsg-group	[...]
                smtp	{
                    action	[...]
                    hdrip	[...]
                    local-override	[...]
                    log-all	[...]
                    tag-msg	[...]
                    tag-type	[...]
                }
                spam-bal-table	[...]
                spam-bword-table	[...]
                spam-bword-threshold	[...]
                spam-filtering	[...]
                spam-iptrust-table	[...]
                spam-log	[...]
                spam-log-fortiguard-response	[...]
                spam-mheader-table	[...]
                spam-rbl-table	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/emailfilter/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/emailfilter/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/emailfilter/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_emailfilter_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_emailfilter_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_filefilter_profile(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_filefilter_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/file-filter/profile*
            */pm/config/global/obj/file-filter/profile/{profile}*
            */pm/config/adom/{adom}/obj/file-filter/profile*
            */pm/config/adom/{adom}/obj/file-filter/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, extended-log, feature-set, log, name, replacemsg-group, scan-archive-contents*

        Examples:
        ---------\n
        >>> init_variable.confdb_filefilter_profile(adom="ADOM Name", profile="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                extended-log	[...]
                feature-set	[...]
                log	[...]
                name	[...]
                replacemsg-group	[...]
                rules	[{
                    action	[...]
                    comment	[...]
                    direction	[...]
                    file-type	[...]
                    name	[...]
                    password-protected	[...]
                    protocol	[...]
                }]
                scan-archive-contents	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/file-filter/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/file-filter/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/file-filter/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/file-filter/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_filefilter_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_filefilter_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_sshfilter_profile(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_sshfilter_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/ssh-filter/profile*
            */pm/config/global/obj/ssh-filter/profile/{profile}*
            */pm/config/adom/{adom}/obj/ssh-filter/profile*
            */pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *block, default-command-log, log, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_sshfilter_profile(adom="ADOM Name", profile="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                block	[...]
                default-command-log	[...]
                log	[...]
                name	[...]
                shell-commands	[{
                    action	[...]
                    alert	[...]
                    id	[...]
                    log	[...]
                    pattern	[...]
                    severity	[...]
                    type	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/ssh-filter/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/ssh-filter/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/ssh-filter/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_sshfilter_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_sshfilter_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_webfilter_profile(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_webfilter_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/webfilter/profile*
            */pm/config/global/obj/webfilter/profile/{profile}*
            */pm/config/adom/{adom}/obj/webfilter/profile*
            */pm/config/adom/{adom}/obj/webfilter/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, extended-log, feature-set, https-replacemsg, log-all-url, name, options, ovrd-perm, post-action, replacemsg-group, web-antiphishing-log, web-content-log, web-extended-all-action-log, web-filter-activex-log, web-filter-applet-log, web-filter-command-block-log, web-filter-cookie-log, web-filter-cookie-removal-log, web-filter-js-log, web-filter-jscript-log, web-filter-referer-log, web-filter-unknown-log, web-filter-vbs-log, web-flow-log-encoding, web-ftgd-err-log, web-ftgd-quota-usage, web-invalid-domain-log, web-url-log, wisp, wisp-algorithm, wisp-servers*

        Examples:
        ---------\n
        >>> init_variable.confdb_webfilter_profile(adom="ADOM Name", profile="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                antiphish	{
                    authentication	[...]
                    check-basic-auth	[...]
                    check-uri	[...]
                    check-username-only	[...]
                    custom-patterns	[{
                        category	[...]
                        pattern	[...]
                        type	[...]
                }]
                default-action	[...]
                domain-controller	[...]
                inspection-entries	[{
                    action	[...]
                    fortiguard-category	[...]
                    name	[...]
                }]
                ldap	[...]
                max-body-len	[...]
                status	[...]
                }
                comment	[...]
                extended-log	[...]
                feature-set	[...]
                ftgd-wf	{
                    exempt-quota	[...]
                    filters	[{
                        action	[...]
                        auth-usr-grp	[...]
                        category	[...]
                        id	[...]
                        log	[...]
                        override-replacemsg	[...]
                        warn-duration	[...]
                        warning-duration-type	[...]
                        warning-prompt	[...]
                    }]
                    max-quota-timeout	[...]
                    options	[...]
                    ovrd	[...]
                    quota	[{
                        category	[...]
                        duration	[...]
                        id	[...]
                        override-replacemsg	[...]
                        type	[...]
                        unit	[...]
                        value	[...]
                    }]
                    rate-crl-urls	[...]
                    rate-css-urls	[...]
                    rate-javascript-urls	[...]
                }
                https-replacemsg	[...]
                log-all-url	[...]
                name	[...]
                options	[...]
                override	{
                    ovrd-cookie	[...]
                    ovrd-dur	[...]
                    ovrd-dur-mode	[...]
                    ovrd-scope	[...]
                    ovrd-user-group	[...]
                    profile	[...]
                    profile-attribute	[...]
                    profile-type	[...]
                }
                ovrd-perm	[...]
                post-action	[...]
                replacemsg-group	[...]
                url-extraction	{
                    redirect-header	[...]
                    redirect-no-content	[...]
                    redirect-url	[...]
                    server-fqdn	[...]
                    status	[...]
                }
                web	{
                    allowlist	[...]
                    blocklist	[...]
                    bword-table	[...]
                    bword-threshold	[...]
                    content-header-list	[...]
                    keyword-match	[...]
                    log-search	[...]
                    safe-search	[...]
                    urlfilter-table	[...]
                    vimeo-restrict	[...]
                    youtube-restrict	[...]
                }
                web-antiphishing-log	[...]
                web-content-log	[...]
                web-extended-all-action-log	[...]
                web-filter-activex-log	[...]
                web-filter-applet-log	[...]
                web-filter-command-block-log	[...]
                web-filter-cookie-log	[...]
                web-filter-cookie-removal-log	[...]
                web-filter-js-log	[...]
                web-filter-jscript-log	[...]
                web-filter-referer-log	[...]
                web-filter-unknown-log	[...]
                web-filter-vbs-log	[...]
                web-flow-log-encoding	[...]
                web-ftgd-err-log	[...]
                web-ftgd-quota-usage	[...]
                web-invalid-domain-log	[...]
                web-url-log	[...]
                wisp	[...]
                wisp-algorithm	[...]
                wisp-servers	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/webfilter/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/webfilter/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/webfilter/profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/webfilter/profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_webfilter_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_webfilter_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_webfilter_urlfilter(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_webfilter_urlfilter\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/webfilter/urlfilter*
            */pm/config/global/obj/webfilter/urlfilter/{urlfilter}*
            */pm/config/adom/{adom}/obj/webfilter/urlfilter*
            */pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, id, ip-addr-block, ip4-mapped-ip6, name, one-arm-ips-urlfilter*

        Examples:
        ---------\n
        >>> init_variable.confdb_webfilter_urlfilter(adom="ADOM Name", profile="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                entries	[{
                    action	[...]
                    antiphish-action	[...]
                    dns-address-family	[...]
                    exempt	[...]
                    id	[...]
                    referrer-host	[...]
                    status	[...]
                    type	[...]
                    url	[...]
                    web-proxy-profile	[...]
                }]
                id	[...]
                ip-addr-block	[...]
                ip4-mapped-ip6	[...]
                name	[...]
                one-arm-ips-urlfilter	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/webfilter/urlfilter/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/webfilter/urlfilter", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/webfilter/urlfilter/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/webfilter/urlfilter", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_webfilter_urlfilter.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_webfilter_urlfilter.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_sslprofile(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_sslprofile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/ssl-ssh-profile*
            */pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}*
            */pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile*
            */pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *allowlist, block-blocklisted-certificates, caname, comment, mapi-over-https, name, rpc-over-https, server-cert, server-cert-mode, ssl-anomaly-log, ssl-exemption-ip-rating, ssl-exemption-log, ssl-handshake-log, ssl-negotiation-log, ssl-server-cert-log, supported-alpn, untrusted-caname, use-ssl-server*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_sslprofile(adom="ADOM Name", profile="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                allowlist	[...]
                block-blocklisted-certificates	[...]
                caname	[...]
                comment	[...]
                dot	{
                    cert-validation-failure	[...]
                    cert-validation-timeout	[...]
                    client-certificate	[...]
                    expired-server-cert	[...]
                    proxy-after-tcp-handshake	[...]
                    quic	[...]
                    revoked-server-cert	[...]
                    sni-server-cert-check	[...]
                    status	[...]
                    unsupported-ssl-cipher	[...]
                    unsupported-ssl-negotiation	[...]
                    unsupported-ssl-version	[...]
                    untrusted-server-cert	[...]
                }
                ech-outer-sni	[{
                    name	[...]
                    sni	[...]
                }]
                ftps	{
                    cert-validation-failure	[...]
                    cert-validation-timeout	[...]
                    client-certificate	[...]
                    expired-server-cert	[...]
                    min-allowed-ssl-version	[...]
                    ports	[...]
                    revoked-server-cert	[...]
                    sni-server-cert-check	[...]
                    status	[...]
                    unsupported-ssl-cipher	[...]
                    unsupported-ssl-negotiation	[...]
                    unsupported-ssl-version	[...]
                    untrusted-server-cert	[...]
                }
                https	{
                    cert-probe-failure	[...]
                    cert-validation-failure	[...]
                    cert-validation-timeout	[...]
                    client-certificate	[...]
                    encrypted-client-hello	[...]
                    expired-server-cert	[...]
                    min-allowed-ssl-version	[...]
                    ports	[...]
                    proxy-after-tcp-handshake	[...]
                    quic	[...]
                    revoked-server-cert	[...]
                    sni-server-cert-check	[...]
                    status	[...]
                    unsupported-ssl-cipher	[...]
                    unsupported-ssl-negotiation	[...]
                    unsupported-ssl-version	[...]
                    untrusted-server-cert	[...]
                }
                imaps	{
                    cert-validation-failure	[...]
                    cert-validation-timeout	[...]
                    client-certificate	[...]
                    expired-server-cert	[...]
                    ports	[...]
                    proxy-after-tcp-handshake	[...]
                    revoked-server-cert	[...]
                    sni-server-cert-check	[...]
                    status	[...]
                    unsupported-ssl-cipher	[...]
                    unsupported-ssl-negotiation	[...]
                    unsupported-ssl-version	[...]
                    untrusted-server-cert	[...]
                }
                mapi-over-https	[...]
                name	[...]
                pop3s	{
                    cert-validation-failure	[...]
                    cert-validation-timeout	[...]
                    client-certificate	[...]
                    expired-server-cert	[...]
                    ports	[...]
                    proxy-after-tcp-handshake	[...]
                    revoked-server-cert	[...]
                    sni-server-cert-check	[...]
                    status	[...]
                    unsupported-ssl-cipher	[...]
                    unsupported-ssl-negotiation	[...]
                    unsupported-ssl-version	[...]
                    untrusted-server-cert	[...]
                }
                rpc-over-https	[...]
                server-cert	[...]
                server-cert-mode	[...]
                smtps	{
                    cert-validation-failure	[...]
                    cert-validation-timeout	[...]
                    client-certificate	[...]
                    expired-server-cert	[...]
                    ports	[...]
                    proxy-after-tcp-handshake	[...]
                    revoked-server-cert	[...]
                    sni-server-cert-check	[...]
                    status	[...]
                    unsupported-ssl-cipher	[...]
                    unsupported-ssl-negotiation	[...]
                    unsupported-ssl-version	[...]
                    untrusted-server-cert	[...]
                }
                ssh	{
                    inspect-all	[...]
                    ports	[...]
                    proxy-after-tcp-handshake	[...]
                    ssh-algorithm	[...]
                    ssh-tun-policy-check	[...]
                    status	[...]
                    unsupported-version	[...]
                }
                ssl	{
                    cert-probe-failure	[...]
                    cert-validation-failure	[...]
                    cert-validation-timeout	[...]
                    client-certificate	[...]
                    encrypted-client-hello	[...]
                    expired-server-cert	[...]
                    inspect-all	[...]
                    min-allowed-ssl-version	[...]
                    revoked-server-cert	[...]
                    sni-server-cert-check	[...]
                    unsupported-ssl-cipher	[...]
                    unsupported-ssl-negotiation	[...]
                    unsupported-ssl-version	[...]
                    untrusted-server-cert	[...]
                }
                ssl-anomaly-log	[...]
                ssl-exempt	[{
                    address	[...]
                    address6	[...]
                    fortiguard-category	[...]
                    id	[...]
                    regex	[...]
                    type	[...]
                    wildcard-fqdn	[...]
                }]
                ssl-exemption-ip-rating	[...]
                ssl-exemption-log	[...]
                ssl-handshake-log	[...]
                ssl-negotiation-log	[...]
                ssl-server	[{
                    ftps-client-certificate	[...]
                    https-client-certificate	[...]
                    id	[...]
                    imaps-client-certificate	[...]
                    ip	[...]
                    pop3s-client-certificate	[...]
                    smtps-client-certificate	[...]
                    ssl-other-client-certificate	[...]
                }]
                ssl-server-cert-log	[...]
                supported-alpn	[...]
                untrusted-caname	[...]
                use-ssl-server	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/ssl-ssh-profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/ssl-ssh-profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_sslprofile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_sslprofile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_address(self, adom:str=None, address:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_address\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/address*
            */pm/config/global/obj/firewall/address/{address}*
            */pm/config/adom/{adom}/obj/firewall/address*
            */pm/config/adom/{adom}/obj/firewall/address/{address}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *_image-base64, allow-routing, associated-interface, cache-ttl, clearpass-spt, color, comment, country, dirty, end-ip, epg-name, fabric-object, filter, fqdn, fsso-group, hw-model, hw-vendor, interface, macaddr, name, node-ip-only, obj-id, obj-tag, obj-type, organization, os, policy-group, route-tag, sdn, sdn-addr-type, sdn-tag, start-ip, sub-type, subnet, subnet-name, sw-version, tag-detection-level, tag-type, tenant, type, uuid, wildcard, wildcard-fqdn*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_address(adom="ADOM Name", address="Address Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                _image-base64	[...]
                allow-routing	[...]
                associated-interface	[...]
                cache-ttl	[...]
                clearpass-spt	[...]
                color	[...]
                comment	[...]
                country	[...]
                dirty	[...]
                dynamic_mapping	[{
                    _image-base64	[...]
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    allow-routing	[...]
                    associated-interface	[...]
                    cache-ttl	[...]
                    clearpass-spt	[...]
                    color	[...]
                    comment	[...]
                    country	[...]
                    dirty	[...]
                    end-ip	[...]
                    end-mac	[...]
                    epg-name	[...]
                    fabric-object	[...]
                    filter	[...]
                    fqdn	[...]
                    fsso-group	[...]
                    global-object	[...]
                    hw-model	[...]
                    hw-vendor	[...]
                    interface	[...]
                    macaddr	[...]
                    node-ip-only	[...]
                    obj-id	[...]
                    obj-tag	[...]
                    obj-type	[...]
                    organization	[...]
                    os	[...]
                    pattern-end	[...]
                    pattern-start	[...]
                    policy-group	[...]
                    route-tag	[...]
                    sdn	[...]
                    sdn-addr-type	[...]
                    sdn-tag	[...]
                    start-ip	[...]
                    start-mac	[...]
                    sub-type	[...]
                    subnet	[...]
                    subnet-name	[...]
                    sw-version	[...]
                    tag-detection-level	[...]
                    tag-type	[...]
                    tags	[...]
                    tenant	[...]
                    type	[...]
                    url	[...]
                    uuid	[...]
                    visibility	[...]
                    wildcard	[...]
                    wildcard-fqdn	[...]
                }]
                end-ip	[...]
                epg-name	[...]
                fabric-object	[...]
                filter	[...]
                fqdn	[...]
                fsso-group	[...]
                hw-model	[...]
                hw-vendor	[...]
                interface	[...]
                list	[{
                    ip	[...]
                    net-id	[...]
                    obj-id	[...]
                }]
                macaddr	[...]
                name	[...]
                node-ip-only	[...]
                obj-id	[...]
                obj-tag	[...]
                obj-type	[...]
                organization	[...]
                os	[...]
                policy-group	[...]
                route-tag	[...]
                sdn	[...]
                sdn-addr-type	[...]
                sdn-tag	[...]
                start-ip	[...]
                sub-type	[...]
                subnet	[...]
                subnet-name	[...]
                sw-version	[...]
                tag-detection-level	[...]
                tag-type	[...]
                tagging	[{
                    category	[...]
                    name	[...]
                    tags	[...]
                }]
                tenant	[...]
                type	[...]
                uuid	[...]
                wildcard	[...]
                wildcard-fqdn	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if address is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/address/{address}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/address", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if address is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/address/{address}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/address", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_address.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_address.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_addrgrp(self, adom:str=None, addrgrp:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_addrgrp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/addrgrp*
            */pm/config/global/obj/firewall/addrgrp/{addrgrp}*
            */pm/config/adom/{adom}/obj/firewall/addrgrp*
            */pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *_image-base64, allow-routing, category, color, comment, exclude, exclude-member, fabric-object, member, name, type, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_addrgrp(adom="ADOM Name", addrgrp="Address Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                _image-base64	[...]
                allow-routing	[...]
                category	[...]
                color	[...]
                comment	[...]
                dynamic_mapping	[{
                    _image-base64	[...]
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    allow-routing	[...]
                    category	[...]
                    color	[...]
                    comment	[...]
                    exclude	[...]
                    exclude-member	[...]
                    fabric-object	[...]
                    global-object	[...]
                    member	[...]
                    tags	[...]
                    type	[...]
                    uuid	[...]
                    visibility	[...]
                }]
                exclude	[...]
                exclude-member	[...]
                fabric-object	[...]
                member	[...]
                name	[...]
                tagging	[{
                    category	[...]
                    name	[...]
                    tags	[...]
                }]
                type	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if addrgrp is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/addrgrp", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if addrgrp is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/addrgrp/{addrgrp}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/addrgrp", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_addrgrp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_addrgrp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_address6(self, adom:str=None, address:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_address6\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/address6*
            */pm/config/global/obj/firewall/address6/{address}*
            */pm/config/adom/{adom}/obj/firewall/address6*
            */pm/config/adom/{adom}/obj/firewall/address6/{address}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *_image-base64, cache-ttl, color, comment, country, end-ip, epg-name, fabric-object, filter, fqdn, host, host-type, ip6, macaddr, name, obj-id, route-tag, sdn, sdn-addr-type, sdn-tag, start-ip, template, tenant, type, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_address6(adom="ADOM Name", address="Address Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                _image-base64	[...]
                cache-ttl	[...]
                color	[...]
                comment	[...]
                country	[...]
                dynamic_mapping	[{
                    _image-base64	[...]
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    cache-ttl	[...]
                    color	[...]
                    comment	[...]
                    country	[...]
                    end-ip	[...]
                    end-mac	[...]
                    epg-name	[...]
                    fabric-object	[...]
                    filter	[...]
                    fqdn	[...]
                    global-object	[...]
                    host	[...]
                    host-type	[...]
                    ip6	[...]
                    macaddr	[...]
                    obj-id	[...]
                    route-tag	[...]
                    sdn	[...]
                    sdn-addr-type	[...]
                    sdn-tag	[...]
                    start-ip	[...]
                    start-mac	[...]
                    subnet-segment	[{
                        name	[...]
                        type	[...]
                        value	[...]
                    }]
                    tags	[...]
                    template	[...]
                    tenant	[...]
                    type	[...]
                    uuid	[...]
                    visibility	[...]
                }]
                end-ip	[...]
                epg-name	[...]
                fabric-object	[...]
                filter	[...]
                fqdn	[...]
                host	[...]
                host-type	[...]
                ip6	[...]
                list	[{
                    ip	[...]
                    net-id	[...]
                    obj-id	[...]
                }]
                macaddr	[...]
                name	[...]
                obj-id	[...]
                route-tag	[...]
                sdn	[...]
                sdn-addr-type	[...]
                sdn-tag	[...]
                start-ip	[...]
                subnet-segment	[{
                    name	[...]
                    type	[...]
                    value	[...]
                }]
                tagging	[{
                    category	[...]
                    name	[...]
                    tags	[...]
                }]
                template	[...]
                tenant	[...]
                type	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if address is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/address6/{address}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/address6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if address is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/address6/{address}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/address6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_address6.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_address6.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_addrgrp6(self, adom:str=None, addrgrp:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_addrgrp6\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/addrgrp6*
            */pm/config/global/obj/firewall/addrgrp6/{addrgrp6}*
            */pm/config/adom/{adom}/obj/firewall/addrgrp6*
            */pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *_image-base64, color, comment, exclude, exclude-member, fabric-object, member, name, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_addrgrp6(adom="ADOM Name", addrgrp="Address Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                _image-base64	[...]
                color	[...]
                comment	[...]
                dynamic_mapping	[{
                    _image-base64	[...]
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    color	[...]
                    comment	[...]
                    exclude	[...]
                    exclude-member	[...]
                    fabric-object	[...]
                    global-object	[...]
                    member	[...]
                    tags	[...]
                    uuid	[...]
                    visibility	[...]
                }]
                exclude	[...]
                exclude-member	[...]
                fabric-object	[...]
                member	[...]
                name	[...]
                tagging	[{
                    category	[...]
                    name	[...]
                    tags	[...]
                }]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if addrgrp is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/addrgrp6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if addrgrp is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/addrgrp6/{addrgrp}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/addrgrp6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_addrgrp6.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_addrgrp6.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_isdb_custom(self, adom:str=None, isdb:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_isdb_custom\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/internet-service-custom*
            */pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}*
            */pm/config/adom/{adom}/obj/firewall/internet-service-custom*
            */pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, id, name, reputation*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_isdb_custom(adom="ADOM Name", isdb="Internet Service Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                entry	[{
                    addr-mode	[...]
                    dst	[...]
                    dst6	[...]
                    id	[...]
                    port-range	[{
                        end-port	[...]
                        id	[...]
                        start-port	[...]
                    }]
                    protocol	[...]
                }]
                id	[...]
                name	[...]
                reputation	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if isdb is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{isdb}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/internet-service-custom", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if isdb is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/internet-service-custom/{isdb}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/internet-service-custom", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_isdb_custom.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_isdb_custom.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_isdb_customgrp(self, adom:str=None, isdb:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_isdb_customgrp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/internet-service-custom-group*
            */pm/config/global/obj/firewall/internet-service-custom-group/{internet-service-custom-group}*
            */pm/config/adom/{adom}/obj/firewall/internet-service-custom-group*
            */pm/config/adom/{adom}/obj/firewall/internet-service-custom-group/{internet-service-custom-group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, member, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_isdb_customgrp(adom="ADOM Name", isdb="Internet Service Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                member	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if isdb is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/internet-service-custom-group/{isdb}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/internet-service-custom-group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if isdb is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/internet-service-custom-group/{isdb}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/internet-service-custom-group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_isdb_customgrp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_isdb_customgrp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_isdb_grp(self, adom:str=None, isdb:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_isdb_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/internet-service-group*
            */pm/config/global/obj/firewall/internet-service-group/{internet-service-group}*
            */pm/config/adom/{adom}/obj/firewall/internet-service-group*
            */pm/config/adom/{adom}/obj/firewall/internet-service-group/{internet-service-group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, direction, member, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_isdb_grp(adom="ADOM Name", isdb="Internet Service Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                direction	[...]
                member	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if isdb is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/internet-service-group/{isdb}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/internet-service-group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if isdb is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/internet-service-group/{isdb}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/internet-service-group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_isdb_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_isdb_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_ippool(self, adom:str=None, pool:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_ippool\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/ippool*
            */pm/config/global/obj/firewall/ippool/{ippool}*
            */pm/config/adom/{adom}/obj/firewall/ippool*
            */pm/config/adom/{adom}/obj/firewall/ippool/{ippool}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *add-nat64-route, arp-intf, arp-reply, associated-interface, block-size, cgn-block-size, cgn-client-endip, cgn-client-ipv6shift, cgn-client-startip, cgn-fixedalloc, cgn-overload, cgn-port-end, cgn-port-start, cgn-spa, comments, endip, endport, exclude-ip, name, nat64, num-blocks-per-user, pba-interim-log, pba-timeout, permit-any-host, port-per-user, source-endip, source-startip, startip, startport, subnet-broadcast-in-ippool, type, utilization-alarm-clear, utilization-alarm-raise*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_ippool(adom="ADOM Name", pool="IP Pool Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                add-nat64-route	[...]
                arp-intf	[...]
                arp-reply	[...]
                associated-interface	[...]
                block-size	[...]
                cgn-block-size	[...]
                cgn-client-endip	[...]
                cgn-client-ipv6shift	[...]
                cgn-client-startip	[...]
                cgn-fixedalloc	[...]
                cgn-overload	[...]
                cgn-port-end	[...]
                cgn-port-start	[...]
                cgn-spa	[...]
                comments	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    add-nat64-route	[...]
                    arp-intf	[...]
                    arp-reply	[...]
                    associated-interface	[...]
                    block-size	[...]
                    cgn-block-size	[...]
                    cgn-client-endip	[...]
                    cgn-client-ipv6shift	[...]
                    cgn-client-startip	[...]
                    cgn-fixedalloc	[...]
                    cgn-overload	[...]
                    cgn-port-end	[...]
                    cgn-port-start	[...]
                    cgn-spa	[...]
                    comments	[...]
                    endip	[...]
                    endport	[...]
                    exclude-ip	[...]
                    nat64	[...]
                    num-blocks-per-user	[...]
                    pba-interim-log	[...]
                    pba-timeout	[...]
                    permit-any-host	[...]
                    port-per-user	[...]
                    source-endip	[...]
                    source-startip	[...]
                    startip	[...]
                    startport	[...]
                    subnet-broadcast-in-ippool	[...]
                    type	[...]
                    utilization-alarm-clear	[...]
                    utilization-alarm-raise	[...]
                }]
                endip	[...]
                endport	[...]
                exclude-ip	[...]
                name	[...]
                nat64	[...]
                num-blocks-per-user	[...]
                pba-interim-log	[...]
                pba-timeout	[...]
                permit-any-host	[...]
                port-per-user	[...]
                source-endip	[...]
                source-startip	[...]
                startip	[...]
                startport	[...]
                subnet-broadcast-in-ippool	[...]
                type	[...]
                utilization-alarm-clear	[...]
                utilization-alarm-raise	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if pool is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/ippool/{pool}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/ippool", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if pool is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/ippool/{pool}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/ippool", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_ippool.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_ippool.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_ippool6(self, adom:str=None, pool:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_ippool6\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/ippool6*
            */pm/config/global/obj/firewall/ippool6/{ippool}*
            */pm/config/adom/{adom}/obj/firewall/ippool6*
            */pm/config/adom/{adom}/obj/firewall/ippool6/{ippool}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *add-nat46-route, comments, endip, name, nat46, startip*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_ippool6(adom="ADOM Name", pool="IP Pool Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                add-nat46-route	[...]
                comments	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    add-nat46-route	[...]
                    comments	[...]
                    endip	[...]
                    nat46	[...]
                    startip	[...]
                }]
                endip	[...]
                name	[...]
                nat46	[...]
                startip	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if pool is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/ippool6/{pool}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/ippool6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if pool is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/ippool6/{pool}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/ippool6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_ippool6.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_ippool6.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_ippoolgrp(self, adom:str=None, poolgrp:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_ippoolgrp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/ippool_grp*
            */pm/config/global/obj/firewall/ippool_grp/{ippool_grp}*
            */pm/config/adom/{adom}/obj/firewall/ippool_grp*
            */pm/config/adom/{adom}/obj/firewall/ippool_grp/{ippool_grp}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comments, member, name, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_ippoolgrp(adom="ADOM Name", poolgrp="IP Pool Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comments	[...]
                member	[...]
                name	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if poolgrp is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/ippool_grp/{poolgrp}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/ippool_grp", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if poolgrp is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/ippool_grp/{poolgrp}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/ippool_grp", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_ippoolgrp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_ippoolgrp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_multicast_address(self, adom:str=None, address:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_multicast_address\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/multicast-address*
            */pm/config/global/obj/firewall/multicast-address/{multicast-address}*
            */pm/config/adom/{adom}/obj/firewall/multicast-address*
            */pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *associated-interface, color, comment, end-ip, name, start-ip, subnet, type*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_multicast_address(adom="ADOM Name", address="Address Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                associated-interface	[...]
                color	[...]
                comment	[...]
                end-ip	[...]
                name	[...]
                start-ip	[...]
                subnet	[...]
                tagging	[{
                    category	[...]
                    name	[...]
                    tags	[...]
                }]
                type	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if address is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/multicast-address/{address}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/multicast-address", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if address is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/multicast-address/{address}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/multicast-address", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_multicast_address.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_multicast_address.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_multicast_address6(self, adom:str=None, address:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_multicast_address6\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/multicast-address6*
            */pm/config/global/obj/firewall/multicast-address6/{multicast-address6}*
            */pm/config/adom/{adom}/obj/firewall/multicast-address6*
            */pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *color, comment, ip6, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_multicast_address6(adom="ADOM Name", address="Address Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                color	[...]
                comment	[...]
                ip6	[...]
                name	[...]
                tagging	[{
                    category	[...]
                    name	[...]
                    tags	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if address is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/multicast-address6/{address}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/multicast-address6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if address is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/multicast-address6/{address}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/multicast-address6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_multicast_address6.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_multicast_address6.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_profile_grp(self, adom:str=None, group:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_profile_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/profile-group*
            */pm/config/global/obj/firewall/profile-group/{profile-group}*
            */pm/config/adom/{adom}/obj/firewall/profile-group*
            */pm/config/adom/{adom}/obj/firewall/profile-group/{profile-group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *application-list, av-profile, casb-profile, diameter-filter-profile, dlp-profile, dnsfilter-profile, emailfilter-profile, file-filter-profile, icap-profile, ips-sensor, ips-voip-filter, name, profile-protocol-options, sctp-filter-profile, ssh-filter-profile, ssl-ssh-profile, videofilter-profile, virtual-patch-profile, voip-profile, waf-profile, webfilter-profile*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_profile_grp(adom="ADOM Name", group="Profile Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                application-list	[...]
                av-profile	[...]
                casb-profile	[...]
                diameter-filter-profile	[...]
                dlp-profile	[...]
                dnsfilter-profile	[...]
                emailfilter-profile	[...]
                file-filter-profile	[...]
                icap-profile	[...]
                ips-sensor	[...]
                ips-voip-filter	[...]
                name	[...]
                profile-protocol-options	[...]
                sctp-filter-profile	[...]
                ssh-filter-profile	[...]
                ssl-ssh-profile	[...]
                videofilter-profile	[...]
                virtual-patch-profile	[...]
                voip-profile	[...]
                waf-profile	[...]
                webfilter-profile	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if group is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/profile-group/{group}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/profile-group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if group is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/profile-group/{group}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/profile-group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_profile_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_profile_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_profile_protocolopt(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_profile_protocolopt\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/profile-protocol-options*
            */pm/config/global/obj/firewall/profile-protocol-options/{profile}*
            */pm/config/adom/{adom}/obj/firewall/profile-protocol-options*
            */pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, name, oversize-log, replacemsg-group, rpc-over-http, switching-protocols-log*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_profile_protocolopt(adom="ADOM Name", profile="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                cifs	{
                    domain-controller	[...]
                    options	[...]
                    oversize-limit	[...]
                    ports	[...]
                    scan-bzip2	[...]
                    server-credential-type	[...]
                    server-keytab	[{
                        keytab	[...]
                        password	[...]
                        principal	[...]
                    }]
                    status	[...]
                    tcp-window-maximum	[...]
                    tcp-window-minimum	[...]
                    tcp-window-size	[...]
                    tcp-window-type	[...]
                    uncompressed-nest-limit	[...]
                    uncompressed-oversize-limit	[...]
                }
                comment	[...]
                dns	{
                    ports	[...]
                    status	[...]
                }
                ftp	{
                    comfort-amount	[...]
                    comfort-interval	[...]
                    explicit-ftp-tls	[...]
                    inspect-all	[...]
                    options	[...]
                    oversize-limit	[...]
                    ports	[...]
                    scan-bzip2	[...]
                    ssl-offloaded	[...]
                    status	[...]
                    stream-based-uncompressed-limit	[...]
                    tcp-window-maximum	[...]
                    tcp-window-minimum	[...]
                    tcp-window-size	[...]
                    tcp-window-type	[...]
                    uncompressed-nest-limit	[...]
                    uncompressed-oversize-limit	[...]
                }
                http	{
                    address-ip-rating	[...]
                    block-page-status-code	[...]
                    comfort-amount	[...]
                    comfort-interval	[...]
                    h2c	[...]
                    inspect-all	[...]
                    options	[...]
                    oversize-limit	[...]
                    ports	[...]
                    post-lang	[...]
                    proxy-after-tcp-handshake	[...]
                    range-block	[...]
                    retry-count	[...]
                    scan-bzip2	[...]
                    ssl-offloaded	[...]
                    status	[...]
                    stream-based-uncompressed-limit	[...]
                    streaming-content-bypass	[...]
                    strip-x-forwarded-for	[...]
                    switching-protocols	[...]
                    tcp-window-maximum	[...]
                    tcp-window-minimum	[...]
                    tcp-window-size	[...]
                    tcp-window-type	[...]
                    tunnel-non-http	[...]
                    uncompressed-nest-limit	[...]
                    uncompressed-oversize-limit	[...]
                    unknown-content-encoding	[...]
                    unknown-http-version	[...]
                    verify-dns-for-policy-matching	[...]
                }
                imap	{
                    inspect-all	[...]
                    options	[...]
                    oversize-limit	[...]
                    ports	[...]
                    proxy-after-tcp-handshake	[...]
                    scan-bzip2	[...]
                    ssl-offloaded	[...]
                    status	[...]
                    uncompressed-nest-limit	[...]
                    uncompressed-oversize-limit	[...]
                }
                mail-signature	{
                    signature	[...]
                    status	[...]
                }
                mapi	{
                    options	[...]
                    oversize-limit	[...]
                    ports	[...]
                    scan-bzip2	[...]
                    status	[...]
                    uncompressed-nest-limit	[...]
                    uncompressed-oversize-limit	[...]
                }
                name	[...]
                nntp	{
                    inspect-all	[...]
                    options	[...]
                    oversize-limit	[...]
                    ports	[...]
                    proxy-after-tcp-handshake	[...]
                    scan-bzip2	[...]
                    status	[...]
                    uncompressed-nest-limit	[...]
                    uncompressed-oversize-limit	[...]
                }
                oversize-log	[...]
                pop3	{
                    inspect-all	[...]
                    options	[...]
                    oversize-limit	[...]
                    ports	[...]
                    proxy-after-tcp-handshake	[...]
                    scan-bzip2	[...]
                    ssl-offloaded	[...]
                    status	[...]
                    uncompressed-nest-limit	[...]
                    uncompressed-oversize-limit	[...]
                }
                replacemsg-group	[...]
                rpc-over-http	[...]
                smtp	{
                    inspect-all	[...]
                    options	[...]
                    oversize-limit	[...]
                    ports	[...]
                    proxy-after-tcp-handshake	[...]
                    scan-bzip2	[...]
                    server-busy	[...]
                    ssl-offloaded	[...]
                    status	[...]
                    uncompressed-nest-limit	[...]
                    uncompressed-oversize-limit	[...]
                }
                ssh	{
                    comfort-amount	[...]
                    comfort-interval	[...]
                    options	[...]
                    oversize-limit	[...]
                    scan-bzip2	[...]
                    ssl-offloaded	[...]
                    stream-based-uncompressed-limit	[...]
                    tcp-window-maximum	[...]
                    tcp-window-minimum	[...]
                    tcp-window-size	[...]
                    tcp-window-type	[...]
                    uncompressed-nest-limit	[...]
                    uncompressed-oversize-limit	[...]
                }
                switching-protocols-log	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/profile-protocol-options", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/profile-protocol-options/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/profile-protocol-options", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_profile_protocolopt.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_profile_protocolopt.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_service_category(self, adom:str=None, cat:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_service_category\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/service/category*
            */pm/config/global/obj/firewall/service/category/{category}*
            */pm/config/adom/{adom}/obj/firewall/service/category*
            */pm/config/adom/{adom}/obj/firewall/service/category/{category}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, fabric-object, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_service_category(adom="ADOM Name", cat="Service Category Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                fabric-object	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if cat is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/service/category/{cat}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/service/category", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if cat is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/service/category/{cat}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/service/category", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_service_category.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_service_category.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_service_custom(self, adom:str=None, service:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_service_custom\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/service/custom*
            */pm/config/global/obj/firewall/service/custom/{service}*
            */pm/config/adom/{adom}/obj/firewall/service/custom*
            */pm/config/adom/{adom}/obj/firewall/service/custom/{service}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone, move*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *app-category, app-service-type, application, category, check-reset-range, color, comment, fabric-object, fqdn, helper, icmpcode, icmptype, iprange, name, protocol, protocol-number, proxy, sctp-portrange, session-ttl, tcp-halfclose-timer, tcp-halfopen-timer, tcp-portrange, tcp-rst-timer, tcp-timewait-timer, udp-idle-timer, udp-portrange, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_service_custom(adom="ADOM Name", service="Service Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                app-category	[...]
                app-service-type	[...]
                application	[...]
                category	[...]
                check-reset-range	[...]
                color	[...]
                comment	[...]
                fabric-object	[...]
                fqdn	[...]
                helper	[...]
                icmpcode	[...]
                icmptype	[...]
                iprange	[...]
                name	[...]
                protocol	[...]
                protocol-number	[...]
                proxy	[...]
                sctp-portrange	[...]
                session-ttl	[...]
                tcp-halfclose-timer	[...]
                tcp-halfopen-timer	[...]
                tcp-portrange	[...]
                tcp-rst-timer	[...]
                tcp-timewait-timer	[...]
                udp-idle-timer	[...]
                udp-portrange	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if service is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/service/custom/{service}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/service/custom", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if service is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/service/custom/{service}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/service/custom", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_service_custom.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_service_custom.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_service_grp(self, adom:str=None, group:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_service_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/service/group*
            */pm/config/global/obj/firewall/service/group/{group}*
            */pm/config/adom/{adom}/obj/firewall/service/group*
            */pm/config/adom/{adom}/obj/firewall/service/group/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *color, comment, fabric-object, member, name, proxy, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_service_grp(adom="ADOM Name", group="Service Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                color	[...]
                comment	[...]
                fabric-object	[...]
                member	[...]
                name	[...]
                proxy	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if group is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/service/group/{group}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/service/group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if group is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/service/group/{group}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/service/group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_service_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_service_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_ipshaper(self, adom:str=None, shaper:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_ipshaper\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/shaper/per-ip-shaper*
            */pm/config/global/obj/firewall/shaper/per-ip-shaper/{shaper}*
            */pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper*
            */pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper/{shaper}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *bandwidth-unit, diffserv-forward, diffserv-reverse, diffservcode-forward, diffservcode-rev, max-bandwidth, max-concurrent-session, max-concurrent-tcp-session, max-concurrent-udp-session, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_ipshaper(adom="ADOM Name", shaper="Shaper Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                bandwidth-unit	[...]
                diffserv-forward	[...]
                diffserv-reverse	[...]
                diffservcode-forward	[...]
                diffservcode-rev	[...]
                max-bandwidth	[...]
                max-concurrent-session	[...]
                max-concurrent-tcp-session	[...]
                max-concurrent-udp-session	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if shaper is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper/{shaper}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if shaper is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/shaper/per-ip-shaper/{shaper}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/shaper/per-ip-shaper", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_ipshaper.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_ipshaper.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_trafficshaper(self, adom:str=None, shaper:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_trafficshaper\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/shaper/traffic-shaper*
            */pm/config/global/obj/firewall/shaper/traffic-shaper/{shaper}*
            */pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper*
            */pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper/{shaper}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *bandwidth-unit, cos, cos-marking, cos-marking-method, diffserv, diffservcode, dscp-marking-method, exceed-bandwidth, exceed-class-id, exceed-cos, exceed-dscp, guaranteed-bandwidth, maximum-bandwidth, maximum-cos, maximum-dscp, name, overhead, per-policy, priority*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_trafficshaper(adom="ADOM Name", shaper="Shaper Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                bandwidth-unit	[...]
                cos	[...]
                cos-marking	[...]
                cos-marking-method	[...]
                diffserv	[...]
                diffservcode	[...]
                dscp-marking-method	[...]
                exceed-bandwidth	[...]
                exceed-class-id	[...]
                exceed-cos	[...]
                exceed-dscp	[...]
                guaranteed-bandwidth	[...]
                maximum-bandwidth	[...]
                maximum-cos	[...]
                maximum-dscp	[...]
                name	[...]
                overhead	[...]
                per-policy	[...]
                priority	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if shaper is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper/{shaper}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if shaper is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/shaper/traffic-shaper/{shaper}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/shaper/traffic-shaper", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_trafficshaper.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_trafficshaper.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_shapingprofile(self, adom:str=None, profile:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_shapingprofile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/shaping-profile*
            */pm/config/global/obj/firewall/shaping-profile/{profile}*
            */pm/config/adom/{adom}/obj/firewall/shaping-profile*
            */pm/config/adom/{adom}/obj/firewall/shaping-profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, default-class-id, npu-offloading, profile-name, type*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_shapingprofile(adom="ADOM Name", profile="Shaping Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                default-class-id	[...]
                npu-offloading	[...]
                profile-name	[...]
                shaping-entries	[{
                    burst-in-msec	[...]
                    cburst-in-msec	[...]
                    class-id	[...]
                    guaranteed-bandwidth-percentage	[...]
                    id	[...]
                    limit	[...]
                    max	[...]
                    maximum-bandwidth-percentage	[...]
                    min	[...]
                    priority	[...]
                    red-probability	[...]
                }]
                type	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/shaping-profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/shaping-profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if profile is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/shaping-profile/{profile}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/shaping-profile", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_shapingprofile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_shapingprofile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_trafficclass(self, adom:str=None, tclass:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_trafficclass\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/traffic-class*
            */pm/config/global/obj/firewall/traffic-class/{traffic-class}*
            */pm/config/adom/{adom}/obj/firewall/traffic-class*
            */pm/config/adom/{adom}/obj/firewall/traffic-class/{traffic-class}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *class-id, class-name*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_trafficclass(adom="ADOM Name", tclass="Traffic Class Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                class-id	[...]
                class-name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if tclass is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/traffic-class/{tclass}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/traffic-class", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if tclass is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/traffic-class/{tclass}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/traffic-class", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_trafficclass.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_trafficclass.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_vip(self, adom:str=None, vip:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_vip\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/vip*
            */pm/config/global/obj/firewall/vip/{vip}*
            */pm/config/adom/{adom}/obj/firewall/vip*
            */pm/config/adom/{adom}/obj/firewall/vip/{vip}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone, move*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *add-nat46-route, arp-reply, color, comment, dns-mapping-ttl, extaddr, extintf, extip, extport, gratuitous-arp-interval, gslb-domain-name, gslb-hostname, h2-support, h3-support, http-cookie-age, http-cookie-domain, http-cookie-domain-from-host, http-cookie-generation, http-cookie-path, http-cookie-share, http-ip-header, http-ip-header-name, http-multiplex, http-multiplex-max-concurrent-request, http-multiplex-max-request, http-multiplex-ttl, http-redirect, https-cookie-secure, id, ipv6-mappedip, ipv6-mappedport, ldb-method, mapped-addr, mappedip, mappedport, max-embryonic-connections, monitor, name, nat-source-vip, nat44, nat46, one-click-gslb-server, outlook-web-access, persistence, portforward, portmapping-type, protocol, server-type, service, src-filter, src-vip-filter, srcintf-filter, ssl-accept-ffdhe-groups, ssl-algorithm, ssl-certificate, ssl-client-fallback, ssl-client-rekey-count, ssl-client-renegotiation, ssl-client-session-state-max, ssl-client-session-state-timeout, ssl-client-session-state-type, ssl-dh-bits, ssl-hpkp, ssl-hpkp-age, ssl-hpkp-backup, ssl-hpkp-include-subdomains, ssl-hpkp-primary, ssl-hpkp-report-uri, ssl-hsts, ssl-hsts-age, ssl-hsts-include-subdomains, ssl-http-location-conversion, ssl-http-match-host, ssl-max-version, ssl-min-version, ssl-mode, ssl-pfs, ssl-send-empty-frags, ssl-server-algorithm, ssl-server-max-version, ssl-server-min-version, ssl-server-renegotiation, ssl-server-session-state-max, ssl-server-session-state-timeout, ssl-server-session-state-type, status, type, uuid, weblogic-server, websphere-server*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_vip(adom="ADOM Name", vip="Virtual IP Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                add-nat46-route	[...]
                arp-reply	[...]
                color	[...]
                comment	[...]
                dns-mapping-ttl	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    add-nat46-route	[...]
                    arp-reply	[...]
                    color	[...]
                    comment	[...]
                    dns-mapping-ttl	[...]
                    extaddr	[...]
                    extintf	[...]
                    extip	[...]
                    extport	[...]
                    gratuitous-arp-interval	[...]
                    gslb-domain-name	[...]
                    gslb-hostname	[...]
                    h2-support	[...]
                    h3-support	[...]
                    http-cookie-age	[...]
                    http-cookie-domain	[...]
                    http-cookie-domain-from-host	[...]
                    http-cookie-generation	[...]
                    http-cookie-path	[...]
                    http-cookie-share	[...]
                    http-ip-header	[...]
                    http-ip-header-name	[...]
                    http-multiplex	[...]
                    http-multiplex-max-concurrent-request	[...]
                    http-multiplex-max-request	[...]
                    http-multiplex-ttl	[...]
                    http-redirect	[...]
                    http-supported-max-version	[...]
                    https-cookie-secure	[...]
                    id	[...]
                    ipv6-mappedip	[...]
                    ipv6-mappedport	[...]
                    ldb-method	[...]
                    mapped-addr	[...]
                    mappedip	[...]
                    mappedport	[...]
                    max-embryonic-connections	[...]
                    monitor	[...]
                    nat-source-vip	[...]
                    nat44	[...]
                    nat46	[...]
                    one-click-gslb-server	[...]
                    outlook-web-access	[...]
                    persistence	[...]
                    portforward	[...]
                    portmapping-type	[...]
                    protocol	[...]
                    realservers	[{
                        address	[...]
                        client-ip	[...]
                        health-check-proto	[...]
                        healthcheck	[...]
                        holddown-interval	[...]
                        http-host	[...]
                        id	[...]
                        ip	[...]
                        max-connections	[...]
                        monitor	[...]
                        port	[...]
                        seq	[...]
                        status	[...]
                        translate-host	[...]
                        type	[...]
                        verify-cert	[...]
                        weight	[...]
                    }]
                    server-type	[...]
                    service	[...]
                    src-filter	[...]
                    src-vip-filter	[...]
                    srcintf-filter	[...]
                    ssl-accept-ffdhe-groups	[...]
                    ssl-algorithm	[...]
                    ssl-certificate	[...]
                    ssl-cipher-suites	[{
                        cipher	[...]
                        id	[...]
                        priority	[...]
                        versions	[...]
                    }]
                    ssl-client-fallback	[...]
                    ssl-client-rekey-count	[...]
                    ssl-client-renegotiation	[...]
                    ssl-client-session-state-max	[...]
                    ssl-client-session-state-timeout	[...]
                    ssl-client-session-state-type	[...]
                    ssl-dh-bits	[...]
                    ssl-hpkp	[...]
                    ssl-hpkp-age	[...]
                    ssl-hpkp-backup	[...]
                    ssl-hpkp-include-subdomains	[...]
                    ssl-hpkp-primary	[...]
                    ssl-hpkp-report-uri	[...]
                    ssl-hsts	[...]
                    ssl-hsts-age	[...]
                    ssl-hsts-include-subdomains	[...]
                    ssl-http-location-conversion	[...]
                    ssl-http-match-host	[...]
                    ssl-max-version	[...]
                    ssl-min-version	[...]
                    ssl-mode	[...]
                    ssl-pfs	[...]
                    ssl-send-empty-frags	[...]
                    ssl-server-algorithm	[...]
                    ssl-server-max-version	[...]
                    ssl-server-min-version	[...]
                    ssl-server-renegotiation	[...]
                    ssl-server-session-state-max	[...]
                    ssl-server-session-state-timeout	[...]
                    ssl-server-session-state-type	[...]
                    status	[...]
                    type	[...]
                    uuid	[...]
                    weblogic-server	[...]
                    websphere-server	[...]
                }]
                extaddr	[...]
                extintf	[...]
                extip	[...]
                extport	[...]
                gratuitous-arp-interval	[...]
                gslb-domain-name	[...]
                gslb-hostname	[...]
                gslb-public-ips	[{
                    index	[...]
                    ip	[...]
                }]
                h2-support	[...]
                h3-support	[...]
                http-cookie-age	[...]
                http-cookie-domain	[...]
                http-cookie-domain-from-host	[...]
                http-cookie-generation	[...]
                http-cookie-path	[...]
                http-cookie-share	[...]
                http-ip-header	[...]
                http-ip-header-name	[...]
                http-multiplex	[...]
                http-multiplex-max-concurrent-request	[...]
                http-multiplex-max-request	[...]
                http-multiplex-ttl	[...]
                http-redirect	[...]
                https-cookie-secure	[...]
                id	[...]
                ipv6-mappedip	[...]
                ipv6-mappedport	[...]
                ldb-method	[...]
                mapped-addr	[...]
                mappedip	[...]
                mappedport	[...]
                max-embryonic-connections	[...]
                monitor	[...]
                name	[...]
                nat-source-vip	[...]
                nat44	[...]
                nat46	[...]
                one-click-gslb-server	[...]
                outlook-web-access	[...]
                persistence	[...]
                portforward	[...]
                portmapping-type	[...]
                protocol	[...]
                quic	{
                    ack-delay-exponent	[...]
                    active-connection-id-limit	[...]
                    active-migration	[...]
                    grease-quic-bit	[...]
                    max-ack-delay	[...]
                    max-datagram-frame-size	[...]
                    max-idle-timeout	[...]
                    max-udp-payload-size	[...]
                }
                realservers	[{
                    address	[...]
                    client-ip	[...]
                    healthcheck	[...]
                    holddown-interval	[...]
                    http-host	[...]
                    id	[...]
                    ip	[...]
                    max-connections	[...]
                    monitor	[...]
                    port	[...]
                    status	[...]
                    translate-host	[...]
                    type	[...]
                    verify-cert	[...]
                    weight	[...]
                }]
                server-type	[...]
                service	[...]
                src-filter	[...]
                src-vip-filter	[...]
                srcintf-filter	[...]
                ssl-accept-ffdhe-groups	[...]
                ssl-algorithm	[...]
                ssl-certificate	[...]
                ssl-cipher-suites	[{
                    cipher	[...]
                    priority	[...]
                    versions	[...]
                }]
                ssl-client-fallback	[...]
                ssl-client-rekey-count	[...]
                ssl-client-renegotiation	[...]
                ssl-client-session-state-max	[...]
                ssl-client-session-state-timeout	[...]
                ssl-client-session-state-type	[...]
                ssl-dh-bits	[...]
                ssl-hpkp	[...]
                ssl-hpkp-age	[...]
                ssl-hpkp-backup	[...]
                ssl-hpkp-include-subdomains	[...]
                ssl-hpkp-primary	[...]
                ssl-hpkp-report-uri	[...]
                ssl-hsts	[...]
                ssl-hsts-age	[...]
                ssl-hsts-include-subdomains	[...]
                ssl-http-location-conversion	[...]
                ssl-http-match-host	[...]
                ssl-max-version	[...]
                ssl-min-version	[...]
                ssl-mode	[...]
                ssl-pfs	[...]
                ssl-send-empty-frags	[...]
                ssl-server-algorithm	[...]
                ssl-server-cipher-suites	[{
                    cipher	[...]
                    priority	[...]
                    versions	[...]
                }]
                ssl-server-max-version	[...]
                ssl-server-min-version	[...]
                ssl-server-renegotiation	[...]
                ssl-server-session-state-max	[...]
                ssl-server-session-state-timeout	[...]
                ssl-server-session-state-type	[...]
                status	[...]
                type	[...]
                uuid	[...]
                weblogic-server	[...]
                websphere-server	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if vip is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/vip/{vip}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/vip", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if vip is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/vip/{vip}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/vip", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_vip.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_vip.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_vip6(self, adom:str=None, vip:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_vip6\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/vip6*
            */pm/config/global/obj/firewall/vip6/{vip}*
            */pm/config/adom/{adom}/obj/firewall/vip6*
            */pm/config/adom/{adom}/obj/firewall/vip6/{vip}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone, move*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *add-nat64-route, color, comment, embedded-ipv4-address, extip, extport, h2-support, h3-support, http-cookie-age, http-cookie-domain, http-cookie-domain-from-host, http-cookie-generation, http-cookie-path, http-cookie-share, http-ip-header, http-ip-header-name, http-multiplex, http-redirect, https-cookie-secure, id, ipv4-mappedip, ipv4-mappedport, ldb-method, mappedip, mappedport, max-embryonic-connections, monitor, name, nat-source-vip, nat64, nat66, ndp-reply, outlook-web-access, persistence, portforward, protocol, server-type, src-filter, src-vip-filter, ssl-accept-ffdhe-groups, ssl-algorithm, ssl-certificate, ssl-client-fallback, ssl-client-rekey-count, ssl-client-renegotiation, ssl-client-session-state-max, ssl-client-session-state-timeout, ssl-client-session-state-type, ssl-dh-bits, ssl-hpkp, ssl-hpkp-age, ssl-hpkp-backup, ssl-hpkp-include-subdomains, ssl-hpkp-primary, ssl-hpkp-report-uri, ssl-hsts, ssl-hsts-age, ssl-hsts-include-subdomains, ssl-http-location-conversion, ssl-http-match-host, ssl-max-version, ssl-min-version, ssl-mode, ssl-pfs, ssl-send-empty-frags, ssl-server-algorithm, ssl-server-max-version, ssl-server-min-version, ssl-server-renegotiation, ssl-server-session-state-max, ssl-server-session-state-timeout, ssl-server-session-state-type, type, uuid, weblogic-server, websphere-server*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_vip6(adom="ADOM Name", vip="Virtual IP Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                add-nat64-route	[...]
                color	[...]
                comment	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    add-nat64-route	[...]
                    arp-reply	[...]
                    color	[...]
                    comment	[...]
                    embedded-ipv4-address	[...]
                    extip	[...]
                    extport	[...]
                    h2-support	[...]
                    h3-support	[...]
                    http-cookie-age	[...]
                    http-cookie-domain	[...]
                    http-cookie-domain-from-host	[...]
                    http-cookie-generation	[...]
                    http-cookie-path	[...]
                    http-cookie-share	[...]
                    http-ip-header	[...]
                    http-ip-header-name	[...]
                    http-multiplex	[...]
                    http-redirect	[...]
                    https-cookie-secure	[...]
                    id	[...]
                    ipv4-mappedip	[...]
                    ipv4-mappedport	[...]
                    ldb-method	[...]
                    mappedip	[...]
                    mappedport	[...]
                    max-embryonic-connections	[...]
                    monitor	[...]
                    nat-source-vip	[...]
                    nat64	[...]
                    nat66	[...]
                    ndp-reply	[...]
                    outlook-web-access	[...]
                    persistence	[...]
                    portforward	[...]
                    protocol	[...]
                    realservers	[{
                        client-ip	[...]
                        healthcheck	[...]
                        holddown-interval	[...]
                        http-host	[...]
                        id	[...]
                        ip	[...]
                        max-connections	[...]
                        monitor	[...]
                        port	[...]
                        status	[...]
                        translate-host	[...]
                        weight	[...]
                    }]
                    server-type	[...]
                    src-filter	[...]
                    src-vip-filter	[...]
                    ssl-accept-ffdhe-groups	[...]
                    ssl-algorithm	[...]
                    ssl-certificate	[...]
                    ssl-cipher-suites	[{
                        cipher	[...]
                        priority	[...]
                        versions	[...]
                    }]
                    ssl-client-fallback	[...]
                    ssl-client-rekey-count	[...]
                    ssl-client-renegotiation	[...]
                    ssl-client-session-state-max	[...]
                    ssl-client-session-state-timeout	[...]
                    ssl-client-session-state-type	[...]
                    ssl-dh-bits	[...]
                    ssl-hpkp	[...]
                    ssl-hpkp-age	[...]
                    ssl-hpkp-backup	[...]
                    ssl-hpkp-include-subdomains	[...]
                    ssl-hpkp-primary	[...]
                    ssl-hpkp-report-uri	[...]
                    ssl-hsts	[...]
                    ssl-hsts-age	[...]
                    ssl-hsts-include-subdomains	[...]
                    ssl-http-location-conversion	[...]
                    ssl-http-match-host	[...]
                    ssl-max-version	[...]
                    ssl-min-version	[...]
                    ssl-mode	[...]
                    ssl-pfs	[...]
                    ssl-send-empty-frags	[...]
                    ssl-server-algorithm	[...]
                    ssl-server-max-version	[...]
                    ssl-server-min-version	[...]
                    ssl-server-renegotiation	[...]
                    ssl-server-session-state-max	[...]
                    ssl-server-session-state-timeout	[...]
                    ssl-server-session-state-type	[...]
                    type	[...]
                    uuid	[...]
                    weblogic-server	[...]
                    websphere-server	[...]
                }]
                embedded-ipv4-address	[...]
                extip	[...]
                extport	[...]
                h2-support	[...]
                h3-support	[...]
                http-cookie-age	[...]
                http-cookie-domain	[...]
                http-cookie-domain-from-host	[...]
                http-cookie-generation	[...]
                http-cookie-path	[...]
                http-cookie-share	[...]
                http-ip-header	[...]
                http-ip-header-name	[...]
                http-multiplex	[...]
                http-redirect	[...]
                https-cookie-secure	[...]
                id	[...]
                ipv4-mappedip	[...]
                ipv4-mappedport	[...]
                ldb-method	[...]
                mappedip	[...]
                mappedport	[...]
                max-embryonic-connections	[...]
                monitor	[...]
                name	[...]
                nat-source-vip	[...]
                nat64	[...]
                nat66	[...]
                ndp-reply	[...]
                outlook-web-access	[...]
                persistence	[...]
                portforward	[...]
                protocol	[...]
                quic	{
                    ack-delay-exponent	[...]
                    active-connection-id-limit	[...]
                    active-migration	[...]
                    grease-quic-bit	[...]
                    max-ack-delay	[...]
                    max-datagram-frame-size	[...]
                    max-idle-timeout	[...]
                    max-udp-payload-size	[...]
                }
                realservers	[{
                    client-ip	[...]
                    healthcheck	[...]
                    holddown-interval	[...]
                    http-host	[...]
                    id	[...]
                    ip	[...]
                    max-connections	[...]
                    monitor	[...]
                    port	[...]
                    status	[...]
                    translate-host	[...]
                    weight	[...]
                }]
                server-type	[...]
                src-filter	[...]
                src-vip-filter	[...]
                ssl-accept-ffdhe-groups	[...]
                ssl-algorithm	[...]
                ssl-certificate	[...]
                ssl-cipher-suites	[{
                    cipher	[...]
                    priority	[...]
                    versions	[...]
                }]
                ssl-client-fallback	[...]
                ssl-client-rekey-count	[...]
                ssl-client-renegotiation	[...]
                ssl-client-session-state-max	[...]
                ssl-client-session-state-timeout	[...]
                ssl-client-session-state-type	[...]
                ssl-dh-bits	[...]
                ssl-hpkp	[...]
                ssl-hpkp-age	[...]
                ssl-hpkp-backup	[...]
                ssl-hpkp-include-subdomains	[...]
                ssl-hpkp-primary	[...]
                ssl-hpkp-report-uri	[...]
                ssl-hsts	[...]
                ssl-hsts-age	[...]
                ssl-hsts-include-subdomains	[...]
                ssl-http-location-conversion	[...]
                ssl-http-match-host	[...]
                ssl-max-version	[...]
                ssl-min-version	[...]
                ssl-mode	[...]
                ssl-pfs	[...]
                ssl-send-empty-frags	[...]
                ssl-server-algorithm	[...]
                ssl-server-cipher-suites	[{
                    cipher	[...]
                    priority	[...]
                    versions	[...]
                }]
                ssl-server-max-version	[...]
                ssl-server-min-version	[...]
                ssl-server-renegotiation	[...]
                ssl-server-session-state-max	[...]
                ssl-server-session-state-timeout	[...]
                ssl-server-session-state-type	[...]
                type	[...]
                uuid	[...]
                weblogic-server	[...]
                websphere-server	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if vip is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/vip6/{vip}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/vip6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if vip is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/vip6/{vip}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/vip6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_vip6.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_vip6.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_vip_grp(self, adom:str=None, group:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_vip_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/vipgrp*
            */pm/config/global/obj/firewall/vipgrp/{group}*
            */pm/config/adom/{adom}/obj/firewall/vipgrp*
            */pm/config/adom/{adom}/obj/firewall/vipgrp/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *color, comments, interface, member, name, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_vip_grp(adom="ADOM Name", group="Virtual IP Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                color	[...]
                comments	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    color	[...]
                    comments	[...]
                    interface	[...]
                    member	[...]
                    uuid	[...]
                }]
                interface	[...]
                member	[...]
                name	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if group is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/vipgrp/{group}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/vipgrp", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if group is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/vipgrp/{group}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/vipgrp", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_vip_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_vip_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_vip_grp6(self, adom:str=None, group:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_vip_grp6\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/vipgrp6*
            */pm/config/global/obj/firewall/vipgrp6/{group}*
            */pm/config/adom/{adom}/obj/firewall/vipgrp6*
            */pm/config/adom/{adom}/obj/firewall/vipgrp6/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *color, comments, member, name, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_vip_grp6(adom="ADOM Name", group="Virtual IP Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                color	[...]
                comments	[...]
                member	[...]
                name	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if group is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/vipgrp6/{group}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/vipgrp6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if group is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/vipgrp6/{group}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/vipgrp6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_vip_grp6.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_vip_grp6.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_wildcardfqdn_custom(self, adom:str=None, address:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_wildcardfqdn_custom\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/wildcard-fqdn/custom*
            */pm/config/global/obj/firewall/wildcard-fqdn/custom/{address}*
            */pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom*
            */pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom/{address}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *color, comment, name, uuid, wildcard-fqdn*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_wildcardfqdn_custom(adom="ADOM Name", address="Address Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                color	[...]
                comment	[...]
                name	[...]
                uuid	[...]
                wildcard-fqdn	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if address is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom/{address}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if address is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/wildcard-fqdn/custom/{address}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/wildcard-fqdn/custom", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_wildcardfqdn_custom.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_wildcardfqdn_custom.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_firewall_wildcardfqdn_grp(self, adom:str=None, group:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_firewall_wildcardfqdn_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/firewall/wildcard-fqdn/group*
            */pm/config/global/obj/firewall/wildcard-fqdn/group/{group}*
            */pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/group*
            */pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/group/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *color, comment, member, name, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_firewall_wildcardfqdn_grp(adom="ADOM Name", group="Address Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                color	[...]
                comment	[...]
                member	[...]
                name	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if group is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/group/{group}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if group is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/wildcard-fqdn/group/{group}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/firewall/wildcard-fqdn/group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_firewall_wildcardfqdn_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_firewall_wildcardfqdn_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_fmg_device_blueprint(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_fmg_device_blueprint\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/fmg/device/blueprint*
            */pm/config/global/obj/fmg/device/blueprint/{blueprint}*
            */pm/config/adom/{adom}/obj/fmg/device/blueprint*
            */pm/config/adom/{adom}/obj/fmg/device/blueprint/{blueprint}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *auth-template, cliprofs, description, dev-group, enforce-device-config, folder, ha-config, ha-hbdev, ha-monitor, ha-password, linked-to-model, name, pkg, platform, port-provisioning, prefer-img-ver, prerun-cliprof, prov-type, split-switch-port, template-group, templates*

        Examples:
        ---------\n
        >>> init_variable.confdb_fmg_device_blueprint(adom="ADOM Name", name="Blueprint Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                auth-template	[...]
                cliprofs	[...]
                description	[...]
                dev-group	[...]
                enforce-device-config	[...]
                folder	[...]
                ha-config	[...]
                ha-hbdev	[...]
                ha-monitor	[...]
                ha-password	[...]
                linked-to-model	[...]
                name	[...]
                pkg	[...]
                platform	[...]
                port-provisioning	[...]
                prefer-img-ver	[...]
                prerun-cliprof	[...]
                prov-type	[...]
                split-switch-port	[...]
                template-group	[...]
                templates	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/fmg/device/blueprint/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/fmg/device/blueprint", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/fmg/device/blueprint/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/fmg/device/blueprint", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_fmg_device_blueprint.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_fmg_device_blueprint.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_fmg_variable(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_fmg_variable\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/fmg/variable*
            */pm/config/global/obj/fmg/variable/{variable}*
            */pm/config/adom/{adom}/obj/fmg/variable*
            */pm/config/adom/{adom}/obj/fmg/variable/{variable}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *description, name, value*

        Examples:
        ---------\n
        >>> init_variable.confdb_fmg_variable(adom="ADOM Name", name="Variable Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                description	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    value	[...]
                }]
                name	[...]
                value	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/fmg/variable/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/fmg/variable", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/fmg/variable/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/fmg/variable", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_fmg_variable.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_fmg_variable.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_global_ips_sensor(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_global_ips_sensor\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/global/ips/sensor*
            */pm/config/global/obj/global/ips/sensor/{sensor}*
            */pm/config/adom/{adom}/obj/global/ips/sensor*
            */pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *block-malicious-url, comment, extended-log, log, name, replacemsg-group, scan-botnet-connections*

        Examples:
        ---------\n
        >>> init_variable.confdb_global_ips_sensor(adom="ADOM Name", name="IPS Sensor Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                block-malicious-url	[...]
                comment	[...]
                entries	[{
                    action	[...]
                    application	[...]
                    cve	[...]
                    default-action	[...]
                    default-status	[...]
                    exempt-ip	[{
                        dst-ip	[...]
                        id	[...]
                        src-ip	[...]
                    }]
                    id	[...]
                    last-modified	[...]
                    location	[...]
                    log	[...]
                    log-attack-context	[...]
                    log-packet	[...]
                    os	[...]
                    position	[...]
                    protocol	[...]
                    quarantine	[...]
                    quarantine-expiry	[...]
                    quarantine-log	[...]
                    rate-count	[...]
                    rate-duration	[...]
                    rate-mode	[...]
                    rate-track	[...]
                    rule	[...]
                    severity	[...]
                    status	[...]
                    tags	[...]
                    vuln-type	[...]
                }]
                extended-log	[...]
                filter	[{
                    action	[...]
                    application	[...]
                    application(real)	[...]
                    location	[...]
                    location(real)	[...]
                    log	[...]
                    log-packet	[...]
                    name	[...]
                    os	[...]
                    os(real)	[...]
                    protocol	[...]
                    protocol(real)	[...]
                    quarantine	[...]
                    quarantine-expiry	[...]
                    quarantine-log	[...]
                    severity	[...]
                    severity(real)	[...]
                    status	[...]
                }]
                log	[...]
                name	[...]
                override	[{
                    action	[...]
                    exempt-ip	[{
                        dst-ip	[...]
                        id	[...]
                        src-ip	[...]
                    }]
                    log	[...]
                    log-packet	[...]
                    quarantine	[...]
                    quarantine-expiry	[...]
                    quarantine-log	[...]
                    rule-id	[...]
                    status	[...]
                }]
                replacemsg-group	[...]
                scan-botnet-connections	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/global/ips/sensor/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/global/ips/sensor", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/global/ips/sensor/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/global/ips/sensor", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_global_ips_sensor.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_global_ips_sensor.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_ips_custom(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_ips_custom\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/ips/custom*
            */pm/config/global/obj/ips/custom/{signature}*
            */pm/config/adom/{adom}/obj/ips/custom*
            */pm/config/adom/{adom}/obj/ips/custom/{signature}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *action, application, comment, location, log, log-packet, os, protocol, rule-id, severity, sig-name, signature, status, tag*

        Examples:
        ---------\n
        >>> init_variable.confdb_ips_custom(adom="ADOM Name", name="IPS Signature Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                action	[...]
                application	[...]
                comment	[...]
                location	[...]
                log	[...]
                log-packet	[...]
                os	[...]
                protocol	[...]
                rule-id	[...]
                severity	[...]
                sig-name	[...]
                signature	[...]
                status	[...]
                tag	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/ips/custom/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/ips/custom", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/ips/custom/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/ips/custom", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_ips_custom.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_ips_custom.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_ips_sensor(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_ips_sensor\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/ips/sensor*
            */pm/config/global/obj/ips/sensor/{sensor}*
            */pm/config/adom/{adom}/obj/ips/sensor*
            */pm/config/adom/{adom}/obj/ips/sensor/{sensor}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *block-malicious-url, comment, extended-log, name, replacemsg-group, scan-botnet-connections*

        Examples:
        ---------\n
        >>> init_variable.confdb_ips_sensor(adom="ADOM Name", name="IPS Sensor Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                block-malicious-url	[...]
                comment	[...]
                entries	[{
                    action	[...]
                    application	[...]
                    cve	[...]
                    default-action	[...]
                    default-status	[...]
                    exempt-ip	[{
                        dst-ip	[...]
                        id	[...]
                        src-ip	[...]
                    }]
                    id	[...]
                    last-modified	[...]
                    location	[...]
                    log	[...]
                    log-attack-context	[...]
                    log-packet	[...]
                    os	[...]
                    protocol	[...]
                    quarantine	[...]
                    quarantine-expiry	[...]
                    quarantine-log	[...]
                    rate-count	[...]
                    rate-duration	[...]
                    rate-mode	[...]
                    rate-track	[...]
                    rule	[...]
                    severity	[...]
                    status	[...]
                    vuln-type	[...]
                }]
                extended-log	[...]
                name	[...]
                replacemsg-group	[...]
                scan-botnet-connections	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/ips/sensor/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/ips/sensor", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/ips/sensor/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/ips/sensor", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_ips_sensor.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_ips_sensor.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_log_customfield(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_log_customfield\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/log/custom-field*
            */pm/config/global/obj/log/custom-field/{name}*
            */pm/config/adom/{adom}/obj/log/custom-field*
            */pm/config/adom/{adom}/obj/log/custom-field/{name}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *id, name, value*

        Examples:
        ---------\n
        >>> init_variable.confdb_log_customfield(adom="ADOM Name", name="Log Field Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                id	[...]
                name	[...]
                value	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/log/custom-field/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/log/custom-field", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/log/custom-field/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/log/custom-field", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_log_customfield.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_log_customfield.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_router_accesslist(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_router_accesslist\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/router/access-list*
            */pm/config/global/obj/router/access-list/{access-list}*
            */pm/config/adom/{adom}/obj/router/access-list*
            */pm/config/adom/{adom}/obj/router/access-list/{access-list}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comments, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_router_accesslist(adom="ADOM Name", name="Access List Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comments	[...]
                name	[...]
                rule	[{
                    action	[...]
                    exact-match	[...]
                    flags	[...]
                    id	[...]
                    prefix	[...]
                    wildcard	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/access-list/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/access-list", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/access-list/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/access-list", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_router_accesslist.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_router_accesslist.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_router_accesslist6(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_router_accesslist6\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/router/access-list6*
            */pm/config/global/obj/router/access-list6/{access-list}*
            */pm/config/adom/{adom}/obj/router/access-list6*
            */pm/config/adom/{adom}/obj/router/access-list6/{access-list}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comments, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_router_accesslist6(adom="ADOM Name", name="Access List Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comments	[...]
                name	[...]
                rule	[{
                    action	[...]
                    exact-match	[...]
                    flags	[...]
                    id	[...]
                    prefix6	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/access-list6/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/access-list6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/access-list6/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/access-list6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_router_accesslist6.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_router_accesslist6.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_router_aspathlist(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_router_aspathlist\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/router/aspath-list*
            */pm/config/global/obj/router/aspath-list/{aspath-list}*
            */pm/config/adom/{adom}/obj/router/aspath-list*
            */pm/config/adom/{adom}/obj/router/aspath-list/{aspath-list}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *name*

        Examples:
        ---------\n
        >>> init_variable.confdb_router_aspathlist(adom="ADOM Name", name="AS Path List Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                name	[...]
                rule	[{
                    action	[...]
                    id	[...]
                    regexp	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/aspath-list/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/aspath-list", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/aspath-list/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/aspath-list", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_router_aspathlist.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_router_aspathlist.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_router_communitylist(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_router_communitylist\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/router/community-list*
            */pm/config/global/obj/router/community-list/{community-list}*
            */pm/config/adom/{adom}/obj/router/community-list*
            */pm/config/adom/{adom}/obj/router/community-list/{community-list}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *name, type*

        Examples:
        ---------\n
        >>> init_variable.confdb_router_communitylist(adom="ADOM Name", name="Community List Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                name	[...]
                rule	[{
                    action	[...]
                    id	[...]
                    match	[...]
                    regexp	[...]
                }]
                type	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/community-list/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/community-list", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/community-list/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/community-list", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_router_communitylist.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_router_communitylist.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_router_prefixlist(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_router_prefixlist\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/router/prefix-list*
            */pm/config/global/obj/router/prefix-list/{prefix-list}*
            */pm/config/adom/{adom}/obj/router/prefix-list*
            */pm/config/adom/{adom}/obj/router/prefix-list/{prefix-list}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comments, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_router_prefixlist(adom="ADOM Name", name="Prefix List Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comments	[...]
                name	[...]
                rule	[{
                    action	[...]
                    flags	[...]
                    ge	[...]
                    id	[...]
                    le	[...]
                    prefix	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/prefix-list/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/prefix-list", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/prefix-list/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/prefix-list", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_router_prefixlist.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_router_prefixlist.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_router_prefixlist6(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_router_prefixlist6\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/router/prefix-list6*
            */pm/config/global/obj/router/prefix-list6/{prefix-list}*
            */pm/config/adom/{adom}/obj/router/prefix-list6*
            */pm/config/adom/{adom}/obj/router/prefix-list6/{prefix-list}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comments, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_router_prefixlist6(adom="ADOM Name", name="Prefix List Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comments	[...]
                name	[...]
                rule	[{
                    action	[...]
                    flags	[...]
                    ge	[...]
                    id	[...]
                    le	[...]
                    prefix6	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/prefix-list6/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/prefix-list6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/prefix-list6/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/prefix-list6", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_router_prefixlist6.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_router_prefixlist6.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_router_routemap(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_router_routemap\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/router/route-map*
            */pm/config/global/obj/router/route-map/{route-map}*
            */pm/config/adom/{adom}/obj/router/route-map*
            */pm/config/adom/{adom}/obj/router/route-map/{route-map}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comments, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_router_routemap(adom="ADOM Name", name="Route Map Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comments	[...]
                name	[...]
                rule	[{
                    action	[...]
                    id	[...]
                    match-as-path	[...]
                    match-community	[...]
                    match-community-exact	[...]
                    match-extcommunity	[...]
                    match-extcommunity-exact	[...]
                    match-flags	[...]
                    match-interface	[...]
                    match-ip-address	[...]
                    match-ip-nexthop	[...]
                    match-ip6-address	[...]
                    match-ip6-nexthop	[...]
                    match-metric	[...]
                    match-origin	[...]
                    match-route-type	[...]
                    match-tag	[...]
                    match-vrf	[...]
                    set-aggregator-as	[...]
                    set-aggregator-ip	[...]
                    set-aspath	[...]
                    set-aspath-action	[...]
                    set-atomic-aggregate	[...]
                    set-community	[...]
                    set-community-additive	[...]
                    set-community-delete	[...]
                    set-dampening-max-suppress	[...]
                    set-dampening-reachability-half-life	[...]
                    set-dampening-reuse	[...]
                    set-dampening-suppress	[...]
                    set-dampening-unreachability-half-life	[...]
                    set-extcommunity-rt	[...]
                    set-extcommunity-soo	[...]
                    set-flags	[...]
                    set-ip-nexthop	[...]
                    set-ip-prefsrc	[...]
                    set-ip6-nexthop	[...]
                    set-ip6-nexthop-local	[...]
                    set-local-preference	[...]
                    set-metric	[...]
                    set-metric-type	[...]
                    set-origin	[...]
                    set-originator-id	[...]
                    set-priority	[...]
                    set-route-tag	[...]
                    set-tag	[...]
                    set-vpnv4-nexthop	[...]
                    set-vpnv6-nexthop	[...]
                    set-vpnv6-nexthop-local	[...]
                    set-weight	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/route-map/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/router/route-map", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/route-map/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/router/route-map", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_router_routemap.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_router_routemap.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_externalresource(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_externalresource\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/external-resource*
            */pm/config/global/obj/system/external-resource/{external-resource}*
            */pm/config/adom/{adom}/obj/system/external-resource*
            */pm/config/adom/{adom}/obj/system/external-resource/{external-resource}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone, move*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *category, comments, interface, interface-select-method, name, password, refresh-rate, resource, server-identity-check, source-ip, status, type, update-method, user-agent, username, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_externalresource(adom="ADOM Name", name="External Resource Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                category	[...]
                comments	[...]
                interface	[...]
                interface-select-method	[...]
                name	[...]
                password	[...]
                refresh-rate	[...]
                resource	[...]
                server-identity-check	[...]
                source-ip	[...]
                status	[...]
                type	[...]
                update-method	[...]
                user-agent	[...]
                username	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/external-resource/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/external-resource", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/external-resource/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/external-resource", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_externalresource.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_externalresource.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_dhcp_server(self, adom:str=None, id:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_dhcp_server\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/dhcp/server*
            */pm/config/global/obj/system/dhcp/server/{server}*
            */pm/config/adom/{adom}/obj/system/dhcp/server*
            */pm/config/adom/{adom}/obj/system/dhcp/server/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *auto-configuration, auto-managed-status, conflicted-ip-timeout, ddns-auth, ddns-key, ddns-keyname, ddns-server-ip, ddns-ttl, ddns-update, ddns-update-override, ddns-zone, default-gateway, dhcp-settings-from-fortiipam, dns-server1, dns-server2, dns-server3, dns-server4, dns-service, domain, filename, forticlient-on-net-status, id, interface, ip-mode, ipsec-lease-hold, lease-time, mac-acl-default-action, netmask, next-server, ntp-server1, ntp-server2, ntp-server3, ntp-service, relay-agent, server-type, shared-subnet, status, tftp-server, timezone, timezone-option, vci-match, vci-string, wifi-ac-service, wifi-ac1, wifi-ac2, wifi-ac3, wins-server1, wins-server2*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_dhcp_server(adom="ADOM Name", id="DHCP Server ID", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                auto-configuration	[...]
                auto-managed-status	[...]
                conflicted-ip-timeout	[...]
                ddns-auth	[...]
                ddns-key	[...]
                ddns-keyname	[...]
                ddns-server-ip	[...]
                ddns-ttl	[...]
                ddns-update	[...]
                ddns-update-override	[...]
                ddns-zone	[...]
                default-gateway	[...]
                dhcp-settings-from-fortiipam	[...]
                dns-server1	[...]
                dns-server2	[...]
                dns-server3	[...]
                dns-server4	[...]
                dns-service	[...]
                domain	[...]
                exclude-range	[{
                    end-ip	[...]
                    id	[...]
                    lease-time	[...]
                    start-ip	[...]
                    uci-match	[...]
                    uci-string	[...]
                    vci-match	[...]
                    vci-string	[...]
                }]
                filename	[...]
                forticlient-on-net-status	[...]
                id	[...]
                interface	[...]
                ip-mode	[...]
                ip-range	[{
                    end-ip	[...]
                    id	[...]
                    lease-time	[...]
                    start-ip	[...]
                    uci-match	[...]
                    uci-string	[...]
                    vci-match	[...]
                    vci-string	[...]
                }]
                ipsec-lease-hold	[...]
                lease-time	[...]
                mac-acl-default-action	[...]
                netmask	[...]
                next-server	[...]
                ntp-server1	[...]
                ntp-server2	[...]
                ntp-server3	[...]
                ntp-service	[...]
                options	[{
                    code	[...]
                    id	[...]
                    ip	[...]
                    type	[...]
                    uci-match	[...]
                    uci-string	[...]
                    value	[...]
                    vci-match	[...]
                    vci-string	[...]
                }]
                relay-agent	[...]
                reserved-address	[{
                    action	[...]
                    circuit-id	[...]
                    circuit-id-type	[...]
                    description	[...]
                    id	[...]
                    ip	[...]
                    mac	[...]
                    remote-id	[...]
                    remote-id-type	[...]
                    type	[...]
                }]
                server-type	[...]
                shared-subnet	[...]
                status	[...]
                tftp-server	[...]
                timezone	[...]
                timezone-option	[...]
                vci-match	[...]
                vci-string	[...]
                wifi-ac-service	[...]
                wifi-ac1	[...]
                wifi-ac2	[...]
                wifi-ac3	[...]
                wins-server1	[...]
                wins-server2	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if id is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/dhcp/server/{id}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/dhcp/server", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if id is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/dhcp/server/{id}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/dhcp/server", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_dhcp_server.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_dhcp_server.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_fortiguard(self, adom:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_fortiguard\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/fortiguard*
            */pm/config/adom/{adom}/obj/system/fortiguard*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, set, update*
        
        Options:
        --------\n
            *scope member, chksum, datasrc*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_fortiguard(adom="ADOM Name", method="HTTP Method", option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                FDS-license-expiring-days	[...]
                antispam-cache	[...]
                antispam-cache-mpermille	[...]
                antispam-cache-ttl	[...]
                antispam-expiration	[...]
                antispam-force-off	[...]
                antispam-license	[...]
                antispam-timeout	[...]
                anycast-sdns-server-ip	[...]
                anycast-sdns-server-port	[...]
                auto-firmware-upgrade	[...]
                auto-firmware-upgrade-day	[...]
                auto-firmware-upgrade-delay	[...]
                auto-firmware-upgrade-end-hour	[...]
                auto-firmware-upgrade-start-hour	[...]
                auto-join-forticloud	[...]
                ddns-server-ip	[...]
                ddns-server-ip6	[...]
                ddns-server-port	[...]
                fortiguard-anycast	[...]
                fortiguard-anycast-source	[...]
                interface	[...]
                interface-select-method	[...]
                load-balance-servers	[...]
                outbreak-prevention-cache	[...]
                outbreak-prevention-cache-mpermille	[...]
                outbreak-prevention-cache-ttl	[...]
                outbreak-prevention-expiration	[...]
                outbreak-prevention-force-off	[...]
                outbreak-prevention-license	[...]
                outbreak-prevention-timeout	[...]
                persistent-connection	[...]
                port	[...]
                protocol	[...]
                proxy-password	[...]
                proxy-server-ip	[...]
                proxy-server-port	[...]
                proxy-username	[...]
                sandbox-inline-scan	[...]
                sandbox-region	[...]
                sdns-options	[...]
                sdns-server-ip	[...]
                sdns-server-port	[...]
                service-account-id	[...]
                source-ip	[...]
                source-ip6	[...]
                update-build-proxy	[...]
                update-dldb	[...]
                update-extdb	[...]
                update-ffdb	[...]
                update-server-location	[...]
                update-uwdb	[...]
                vdom	[...]
                webfilter-cache	[...]
                webfilter-cache-ttl	[...]
                webfilter-expiration	[...]
                webfilter-force-off	[...]
                webfilter-license	[...]
                webfilter-timeout	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/fortiguard", session=self.session_id, verbose=1, data=data, option=option)
            else:
                self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/fortiguard", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_fortiguard.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_fortiguard.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_geoip_country(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_geoip_country\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/geoip-country*
            */pm/config/global/obj/system/geoip-country/{geoip-country}*
            */pm/config/adom/{adom}/obj/system/geoip-country*
            */pm/config/adom/{adom}/obj/system/geoip-country/{geoip-country}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *id, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_geoip_country(adom="ADOM Name", name="Country Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                id	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/geoip-country/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/geoip-country", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/geoip-country/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/geoip-country", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_geoip_country.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_geoip_country.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_geoip_override(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_geoip_override\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/geoip-override*
            */pm/config/global/obj/system/geoip-override/{geoip-override}*
            */pm/config/adom/{adom}/obj/system/geoip-override*
            */pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *country-id, description, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_geoip_override(adom="ADOM Name", name="Override Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                country-id	[...]
                description	[...]
                ip-range	[{
                    end-ip	[...]
                    id	[...]
                    start-ip	[...]
                }]
                ip6-range	[{
                    end-ip	[...]
                    id	[...]
                    start-ip	[...]
                }]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/geoip-override/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/geoip-override", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/geoip-override/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/geoip-override", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_geoip_override.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_geoip_override.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_meta(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_meta\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/meta*
            */pm/config/global/obj/system/meta/{meta-field}*
            */pm/config/adom/{adom}/obj/system/meta*
            */pm/config/adom/{adom}/obj/system/meta/{meta-field}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *name*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_meta(adom="ADOM Name", name="Meta Field Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                name	[...]
                sys_meta_fields	[{
                    fieldlength	[...]
                    importance	[...]
                    name	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/meta/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/meta", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/meta/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/meta", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_meta.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_meta.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_npu(self, adom:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_npu\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/npu*
            */pm/config/adom/{adom}/obj/system/npu*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, set, update*
        
        Options:
        --------\n
            *scope member, chksum, datasrc*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_npu(adom="ADOM Name", method="HTTP Method", option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                background-sse-scan	{
                    scan	[...]
                    scan-stale	[...]
                    scan-vt	[...]
                    stats-qual-access	[...]
                    stats-qual-duration	[...]
                    stats-update-interval	[...]
                    udp-keepalive-interval	[...]
                    udp-qual-access	[...]
                    udp-qual-duration	[...]
                }
                capwap-offload	[...]
                dedicated-lacp-queue	[...]
                dedicated-management-affinity	[...]
                dedicated-management-cpu	[...]
                default-qos-type	[...]
                default-tcp-refresh-dir	[...]
                default-udp-refresh-dir	[...]
                dos-options	{
                    npu-dos-meter-mode	[...]
                    npu-dos-synproxy-mode	[...]
                    npu-dos-tpe-mode	[...]
                }
                double-level-mcast-offload	[...]
                dse-timeout	[...]
                dsw-dts-profile	[{
                    action	[...]
                    min-limit	[...]
                    profile-id	[...]
                    step	[...]
                }]
                dsw-queue-dts-profile	[{
                    iport	[...]
                    name	[...]
                    oport	[...]
                    profile-id	[...]
                    queue-select	[...]
                }]
                fastpath	[...]
                fp-anomaly	{
                    esp-minlen-err	[...]
                    gre-csum-err	[...]
                    icmp-csum-err	[...]
                    icmp-frag	[...]
                    icmp-land	[...]
                    icmp-minlen-err	[...]
                    ipv4-csum-err	[...]
                    ipv4-ihl-err	[...]
                    ipv4-land	[...]
                    ipv4-len-err	[...]
                    ipv4-opt-err	[...]
                    ipv4-optlsrr	[...]
                    ipv4-optrr	[...]
                    ipv4-optsecurity	[...]
                    ipv4-optssrr	[...]
                    ipv4-optstream	[...]
                    ipv4-opttimestamp	[...]
                    ipv4-proto-err	[...]
                    ipv4-ttlzero-err	[...]
                    ipv4-unknopt	[...]
                    ipv4-ver-err	[...]
                    ipv6-daddr-err	[...]
                    ipv6-exthdr-len-err	[...]
                    ipv6-exthdr-order-err	[...]
                    ipv6-ihl-err	[...]
                    ipv6-land	[...]
                    ipv6-optendpid	[...]
                    ipv6-opthomeaddr	[...]
                    ipv6-optinvld	[...]
                    ipv6-optjumbo	[...]
                    ipv6-optnsap	[...]
                    ipv6-optralert	[...]
                    ipv6-opttunnel	[...]
                    ipv6-plen-zero	[...]
                    ipv6-proto-err	[...]
                    ipv6-saddr-err	[...]
                    ipv6-unknopt	[...]
                    ipv6-ver-err	[...]
                    sctp-csum-err	[...]
                    tcp-csum-err	[...]
                    tcp-fin-noack	[...]
                    tcp-fin-only	[...]
                    tcp-hlen-err	[...]
                    tcp-land	[...]
                    tcp-no-flag	[...]
                    tcp-plen-err	[...]
                    tcp-syn-data	[...]
                    tcp-syn-fin	[...]
                    tcp-winnuke	[...]
                    udp-csum-err	[...]
                    udp-hlen-err	[...]
                    udp-land	[...]
                    udp-len-err	[...]
                    udp-plen-err	[...]
                    udplite-cover-err	[...]
                    udplite-csum-err	[...]
                    unknproto-minlen-err	[...]
                }
                gtp-enhanced-cpu-range	[...]
                gtp-enhanced-mode	[...]
                gtp-support	[...]
                hash-config	[...]
                hash-ipv6-sel	[...]
                hash-tbl-spread	[...]
                host-shortcut-mode	[...]
                hpe	{
                    all-protocol	[...]
                    arp-max	[...]
                    enable-queue-shaper	[...]
                    enable-shaper	[...]
                    esp-max	[...]
                    exception-code	[...]
                    fragment-with-sess	[...]
                    fragment-without-session	[...]
                    high-priority	[...]
                    icmp-max	[...]
                    ip-frag-max	[...]
                    ip-others-max	[...]
                    l2-others-max	[...]
                    queue-shaper-max	[...]
                    sctp-max	[...]
                    tcp-max	[...]
                    tcpfin-rst-max	[...]
                    tcpsyn-ack-max	[...]
                    tcpsyn-max	[...]
                    udp-max	[...]
                }
                htab-dedi-queue-nr	[...]
                htab-msg-queue	[...]
                htx-gtse-quota	[...]
                htx-icmp-csum-chk	[...]
                hw-ha-scan-interval	[...]
                icmp-error-rate-ctrl	{
                    icmpv4-error-bucket-size	[...]
                    icmpv4-error-rate	[...]
                    icmpv4-error-rate-limit	[...]
                    icmpv6-error-bucket-size	[...]
                    icmpv6-error-rate	[...]
                    icmpv6-error-rate-limit	[...]
                }
                icmp-rate-ctrl	{
                    icmp-v4-bucket-size	[...]
                    icmp-v4-rate	[...]
                    icmp-v6-bucket-size	[...]
                    icmp-v6-rate	[...]
                }
                inbound-dscp-copy-port	[...]
                intf-shaping-offload	[...]
                ip-fragment-offload	[...]
                ip-reassembly	{
                    max-timeout	[...]
                    min-timeout	[...]
                    status	[...]
                }
                iph-rsvd-re-cksum	[...]
                ippool-overload-high	[...]
                ippool-overload-low	[...]
                ipsec-STS-timeout	[...]
                ipsec-dec-subengine-mask	[...]
                ipsec-enc-subengine-mask	[...]
                ipsec-inbound-cache	[...]
                ipsec-mtu-override	[...]
                ipsec-ob-np-sel	[...]
                ipsec-ordering	[...]
                ipsec-over-vlink	[...]
                ipsec-throughput-msg-frequency	[...]
                ipt-STS-timeout	[...]
                ipt-throughput-msg-frequency	[...]
                isf-np-queues	{
                    cos0	[...]
                    cos1	[...]
                    cos2	[...]
                    cos3	[...]
                    cos4	[...]
                    cos5	[...]
                    cos6	[...]
                    cos7	[...]
                }
                lag-out-port-select	[...]
                max-receive-unit	[...]
                max-session-timeout	[...]
                mcast-session-accounting	[...]
                napi-break-interval	[...]
                np-queues	{
                    custom-etype-lookup	[...]
                    ethernet-type	[{
                        name	[...]
                        queue	[...]
                        type	[...]
                        weight	[...]
                    }]
                    ip-protocol	[{
                        name	[...]
                        protocol	[...]
                        queue	[...]
                        weight	[...]
                    }]
                    ip-service	[{
                        dport	[...]
                        name	[...]
                        protocol	[...]
                        queue	[...]
                        sport	[...]
                        weight	[...]
                    }]
                    profile	[{
                        cos0	[...]
                        cos1	[...]
                        cos2	[...]
                        cos3	[...]
                        cos4	[...]
                        cos5	[...]
                        cos6	[...]
                        cos7	[...]
                        dscp0	[...]
                        dscp1	[...]
                        dscp10	[...]
                        dscp11	[...]
                        dscp12	[...]
                        dscp13	[...]
                        dscp14	[...]
                        dscp15	[...]
                        dscp16	[...]
                        dscp17	[...]
                        dscp18	[...]
                        dscp19	[...]
                        dscp2	[...]
                        dscp20	[...]
                        dscp21	[...]
                        dscp22	[...]
                        dscp23	[...]
                        dscp24	[...]
                        dscp25	[...]
                        dscp26	[...]
                        dscp27	[...]
                        dscp28	[...]
                        dscp29	[...]
                        dscp3	[...]
                        dscp30	[...]
                        dscp31	[...]
                        dscp32	[...]
                        dscp33	[...]
                        dscp34	[...]
                        dscp35	[...]
                        dscp36	[...]
                        dscp37	[...]
                        dscp38	[...]
                        dscp39	[...]
                        dscp4	[...]
                        dscp40	[...]
                        dscp41	[...]
                        dscp42	[...]
                        dscp43	[...]
                        dscp44	[...]
                        dscp45	[...]
                        dscp46	[...]
                        dscp47	[...]
                        dscp48	[...]
                        dscp49	[...]
                        dscp5	[...]
                        dscp50	[...]
                        dscp51	[...]
                        dscp52	[...]
                        dscp53	[...]
                        dscp54	[...]
                        dscp55	[...]
                        dscp56	[...]
                        dscp57	[...]
                        dscp58	[...]
                        dscp59	[...]
                        dscp6	[...]
                        dscp60	[...]
                        dscp61	[...]
                        dscp62	[...]
                        dscp63	[...]
                        dscp7	[...]
                        dscp8	[...]
                        dscp9	[...]
                        id	[...]
                        type	[...]
                        weight	[...]
                    }]
                    scheduler	[{
                        mode	[...]
                        name	[...]
                    }]
                }
                np6-cps-optimization-mode	[...]
                npu-group-effective-scope	[...]
                npu-tcam	[{
                    data	{
                        df	[...]
                        dstip	[...]
                        dstipv6	[...]
                        dstmac	[...]
                        dstport	[...]
                        ethertype	[...]
                        ext-tag	[...]
                        frag-off	[...]
                        gen-buf-cnt	[...]
                        gen-iv	[...]
                        gen-l3-flags	[...]
                        gen-l4-flags	[...]
                        gen-pkt-ctrl	[...]
                        gen-pri	[...]
                        gen-pri-v	[...]
                        gen-tv	[...]
                        ihl	[...]
                        ip4-id	[...]
                        ip6-fl	[...]
                        ipver	[...]
                        l4-wd10	[...]
                        l4-wd11	[...]
                        l4-wd8	[...]
                        l4-wd9	[...]
                        mf	[...]
                        protocol	[...]
                        slink	[...]
                        smac-change	[...]
                        sp	[...]
                        src-cfi	[...]
                        src-prio	[...]
                        src-updt	[...]
                        srcip	[...]
                        srcipv6	[...]
                        srcmac	[...]
                        srcport	[...]
                        svid	[...]
                        tcp-ack	[...]
                        tcp-cwr	[...]
                        tcp-ece	[...]
                        tcp-fin	[...]
                        tcp-push	[...]
                        tcp-rst	[...]
                        tcp-syn	[...]
                        tcp-urg	[...]
                        tgt-cfi	[...]
                        tgt-prio	[...]
                        tgt-updt	[...]
                        tgt-v	[...]
                        tos	[...]
                        tp	[...]
                        ttl	[...]
                        tvid	[...]
                        vdid	[...]
                    }
                    dbg-dump	[...]
                    mask	{
                        df	[...]
                        dstip	[...]
                        dstipv6	[...]
                        dstmac	[...]
                        dstport	[...]
                        ethertype	[...]
                        ext-tag	[...]
                        frag-off	[...]
                        gen-buf-cnt	[...]
                        gen-iv	[...]
                        gen-l3-flags	[...]
                        gen-l4-flags	[...]
                        gen-pkt-ctrl	[...]
                        gen-pri	[...]
                        gen-pri-v	[...]
                        gen-tv	[...]
                        ihl	[...]
                        ip4-id	[...]
                        ip6-fl	[...]
                        ipver	[...]
                        l4-wd10	[...]
                        l4-wd11	[...]
                        l4-wd8	[...]
                        l4-wd9	[...]
                        mf	[...]
                        protocol	[...]
                        slink	[...]
                        smac-change	[...]
                        sp	[...]
                        src-cfi	[...]
                        src-prio	[...]
                        src-updt	[...]
                        srcip	[...]
                        srcipv6	[...]
                        srcmac	[...]
                        srcport	[...]
                        svid	[...]
                        tcp-ack	[...]
                        tcp-cwr	[...]
                        tcp-ece	[...]
                        tcp-fin	[...]
                        tcp-push	[...]
                        tcp-rst	[...]
                        tcp-syn	[...]
                        tcp-urg	[...]
                        tgt-cfi	[...]
                        tgt-prio	[...]
                        tgt-updt	[...]
                        tgt-v	[...]
                        tos	[...]
                        tp	[...]
                        ttl	[...]
                        tvid	[...]
                        vdid	[...]
                    }
                    mir-act	{
                        vlif	[...]
                    }
                    name	[...]
                    oid	[...]
                    pri-act	{
                        priority	[...]
                        weight	[...]
                    }
                    sact	{
                        act	[...]
                        act-v	[...]
                        bmproc	[...]
                        bmproc-v	[...]
                        df-lif	[...]
                        df-lif-v	[...]
                        dfr	[...]
                        dfr-v	[...]
                        dmac-skip	[...]
                        dmac-skip-v	[...]
                        dosen	[...]
                        dosen-v	[...]
                        espff-proc	[...]
                        espff-proc-v	[...]
                        etype-pid	[...]
                        etype-pid-v	[...]
                        frag-proc	[...]
                        frag-proc-v	[...]
                        fwd	[...]
                        fwd-lif	[...]
                        fwd-lif-v	[...]
                        fwd-tvid	[...]
                        fwd-tvid-v	[...]
                        fwd-v	[...]
                        icpen	[...]
                        icpen-v	[...]
                        igmp-mld-snp	[...]
                        igmp-mld-snp-v	[...]
                        learn	[...]
                        learn-v	[...]
                        m-srh-ctrl	[...]
                        m-srh-ctrl-v	[...]
                        mac-id	[...]
                        mac-id-v	[...]
                        mss	[...]
                        mss-v	[...]
                        pleen	[...]
                        pleen-v	[...]
                        prio-pid	[...]
                        prio-pid-v	[...]
                        promis	[...]
                        promis-v	[...]
                        rfsh	[...]
                        rfsh-v	[...]
                        smac-skip	[...]
                        smac-skip-v	[...]
                        tp-smchk-v	[...]
                        tp_smchk	[...]
                        tpe-id	[...]
                        tpe-id-v	[...]
                        vdm	[...]
                        vdm-v	[...]
                        vdom-id	[...]
                        vdom-id-v	[...]
                        x-mode	[...]
                        x-mode-v	[...]
                    }
                    tact	{
                        act	[...]
                        act-v	[...]
                        fmtuv4-s	[...]
                        fmtuv4-s-v	[...]
                        fmtuv6-s	[...]
                        fmtuv6-s-v	[...]
                        lnkid	[...]
                        lnkid-v	[...]
                        mac-id	[...]
                        mac-id-v	[...]
                        mss-t	[...]
                        mss-t-v	[...]
                        mtuv4	[...]
                        mtuv4-v	[...]
                        mtuv6	[...]
                        mtuv6-v	[...]
                        slif-act	[...]
                        slif-act-v	[...]
                        sublnkid	[...]
                        sublnkid-v	[...]
                        tgtv-act	[...]
                        tgtv-act-v	[...]
                        tlif-act	[...]
                        tlif-act-v	[...]
                        tpeid	[...]
                        tpeid-v	[...]
                        v6fe	[...]
                        v6fe-v	[...]
                        vep-en-v	[...]
                        vep-slid	[...]
                        vep-slid-v	[...]
                        vep_en	[...]
                        xlt-lif	[...]
                        xlt-lif-v	[...]
                        xlt-vid	[...]
                        xlt-vid-v	[...]
                    }
                    type	[...]
                    vid	[...]
                }]
                nss-threads-option	[...]
                pba-eim	[...]
                pba-port-select-mode	[...]
                per-policy-accounting	[...]
                per-session-accounting	[...]
                ple-non-syn-tcp-action	[...]
                policy-offload-level	[...]
                port-cpu-map	[{
                    cpu-core	[...]
                    interface	[...]
                }]
                port-npu-map	[{
                    interface	[...]
                    npu-group-index	[...]
                }]
                port-path-option	{
                    ports-using-npu	[...]
                }
                priority-protocol	{
                    bfd	[...]
                    bgp	[...]
                    slbc	[...]
                }
                prp-session-clear-mode	[...]
                qos-mode	[...]
                qtm-buf-mode	[...]
                rdp-offload	[...]
                session-acct-interval	[...]
                session-denied-offload	[...]
                shaping-stats	[...]
                spa-port-select-mode	[...]
                split-ipsec-engines	[...]
                sse-backpressure	[...]
                sse-ha-scan	{
                    gap	[...]
                    max-session-cnt	[...]
                    min-duration	[...]
                }
                strip-clear-text-padding	[...]
                strip-esp-padding	[...]
                sw-eh-hash	{
                    computation	[...]
                    destination-ip-lower-16	[...]
                    destination-ip-upper-16	[...]
                    destination-port	[...]
                    ip-protocol	[...]
                    netmask-length	[...]
                    source-ip-lower-16	[...]
                    source-ip-upper-16	[...]
                    source-port	[...]
                }
                sw-np-bandwidth	[...]
                sw-np-pause	[...]
                sw-np-rate	[...]
                sw-np-rate-unit	[...]
                sw-tr-hash	{
                    draco15	[...]
                    tcp-udp-port	[...]
                }
                switch-np-hash	[...]
                tcp-rst-timeout	[...]
                tunnel-over-vlink	[...]
                uesp-offload	[...]
                ull-port-mode	[...]
                vlan-lookup-cache	[...]
                vxlan-offload	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/npu", session=self.session_id, verbose=1, data=data, option=option)
            else:
                self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/npu", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_npu.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_npu.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_objecttagging(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_objecttagging\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/object-tagging*
            */pm/config/global/obj/system/object-tagging/{object-tagging}*
            */pm/config/adom/{adom}/obj/system/object-tagging*
            */pm/config/adom/{adom}/obj/system/object-tagging/{object-tagging}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *address, category, color, device, interface, multiple, tags*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_objecttagging(adom="ADOM Name", name="Object Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                address	[...]
                category	[...]
                color	[...]
                device	[...]
                interface	[...]
                multiple	[...]
                tags	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/object-tagging/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/object-tagging", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/object-tagging/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/object-tagging", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_objecttagging.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_objecttagging.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_replacemsg_grp(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_replacemsg_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/replacemsg-group*
            */pm/config/global/obj/system/replacemsg-group/{group}*
            */pm/config/adom/{adom}/obj/system/replacemsg-group*
            */pm/config/adom/{adom}/obj/system/replacemsg-group/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, group-type, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_replacemsg_grp(adom="ADOM Name", name="Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                admin	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                alertmail	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                auth	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                automation	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                comment	[...]
                custom-message	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                fortiguard-wf	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                ftp	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                group-type	[...]
                http	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                icap	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                mail	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                nac-quar	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                name	[...]
                spam	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                sslvpn	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                traffic-quota	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                utm	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
                webproxy	[{
                    buffer	[...]
                    format	[...]
                    header	[...]
                    msg-type	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/replacemsg-group/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/replacemsg-group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/replacemsg-group/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/replacemsg-group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_replacemsg_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_replacemsg_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_replacemsg_image(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_replacemsg_image\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/replacemsg-image*
            */pm/config/global/obj/system/replacemsg-image/{image}*
            */pm/config/adom/{adom}/obj/system/replacemsg-image*
            */pm/config/adom/{adom}/obj/system/replacemsg-image/{image}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *image-base64, image-type, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_replacemsg_image(adom="ADOM Name", name="Image Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                image-base64	[...]
                image-type	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/replacemsg-image/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/replacemsg-image", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/replacemsg-image/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/replacemsg-image", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_replacemsg_image.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_replacemsg_image.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_sdnconnector(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_sdnconnector\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/sdn-connector*
            */pm/config/global/obj/system/sdn-connector/{connector}*
            */pm/config/adom/{adom}/obj/system/sdn-connector*
            */pm/config/adom/{adom}/obj/system/sdn-connector/{connector}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *_local_cert, access-key, alt-resource-ip, api-key, azure-region, client-id, client-secret, compute-generation, domain, group-name, ha-status, ibm-region, key-passwd, login-endpoint, name, oci-cert, oci-fingerprint, oci-region-type, password, private-key, proxy, region, resource-group, resource-url, secret-key, secret-token, server, server-ca-cert, server-cert, server-list, server-port, service-account, status, subscription-id, tenant-id, type, update-interval, use-metadata-iam, user-id, username, vcenter-password, vcenter-server, vcenter-username, verify-certificate, vpc-id*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_sdnconnector(adom="ADOM Name", name="Connector Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                _local_cert	[...]
                access-key	[...]
                alt-resource-ip	[...]
                api-key	[...]
                azure-region	[...]
                client-id	[...]
                client-secret	[...]
                compartment-list	[{
                    compartment-id	[...]
                }]
                compute-generation	[...]
                domain	[...]
                external-account-list	[{
                    external-id	[...]
                    region-list	[...]
                    role-arn	[...]
                }]
                external-ip	[{
                    name	[...]
                }]
                forwarding-rule	[{
                    rule-name	[...]
                    target	[...]
                }]
                gcp-project-list	[{
                    gcp-zone-list	[...]
                    id	[...]
                }]
                group-name	[...]
                ha-status	[...]
                ibm-region	[...]
                key-passwd	[...]
                login-endpoint	[...]
                name	[...]
                nic	[{
                    ip	[{
                        name	[...]
                        private-ip	[...]
                        public-ip	[...]
                        resource-group	[...]
                    }]
                    name	[...]
                    peer-nic	[...]
                }]
                oci-cert	[...]
                oci-fingerprint	[...]
                oci-region-list	[{
                    region	[...]
                }]
                oci-region-type	[...]
                password	[...]
                private-key	[...]
                proxy	[...]
                region	[...]
                resource-group	[...]
                resource-url	[...]
                route	[{
                    name	[...]
                }]
                route-table	[{
                    name	[...]
                    resource-group	[...]
                    route	[{
                        name	[...]
                        next-hop	[...]
                    }]
                    subscription-id	[...]
                }]
                secret-key	[...]
                secret-token	[...]
                server	[...]
                server-ca-cert	[...]
                server-cert	[...]
                server-list	[...]
                server-port	[...]
                service-account	[...]
                status	[...]
                subscription-id	[...]
                tenant-id	[...]
                type	[...]
                update-interval	[...]
                use-metadata-iam	[...]
                user-id	[...]
                username	[...]
                vcenter-password	[...]
                vcenter-server	[...]
                vcenter-username	[...]
                verify-certificate	[...]
                vpc-id	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/sdn-connector/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/sdn-connector", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/sdn-connector/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/sdn-connector", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_sdnconnector.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_sdnconnector.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_sdnproxy(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_sdnproxy\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/sdn-proxy*
            */pm/config/global/obj/system/sdn-proxy/{server}*
            */pm/config/adom/{adom}/obj/system/sdn-proxy*
            */pm/config/adom/{adom}/obj/system/sdn-proxy/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *name, password, server, server-port, type, username*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_sdnproxy(adom="ADOM Name", name="Server Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                name	[...]
                password	[...]
                server	[...]
                server-port	[...]
                type	[...]
                username	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/sdn-proxy/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/sdn-proxy", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/sdn-proxy/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/sdn-proxy", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_sdnproxy.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_sdnproxy.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_smsserver(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_smsserver\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/sms-server*
            */pm/config/global/obj/system/sms-server/{server}*
            */pm/config/adom/{adom}/obj/system/sms-server*
            */pm/config/adom/{adom}/obj/system/sms-server/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *mail-server, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_smsserver(adom="ADOM Name", name="Server Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                mail-server	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/sms-server/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/sms-server", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/sms-server/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/sms-server", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_smsserver.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_smsserver.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_system_virtualwirepair(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_system_virtualwirepair\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/system/virtual-wire-pair*
            */pm/config/global/obj/system/virtual-wire-pair/{virtual-wire-pair}*
            */pm/config/adom/{adom}/obj/system/virtual-wire-pair*
            */pm/config/adom/{adom}/obj/system/virtual-wire-pair/{virtual-wire-pair}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *member, name, outer-vlan-id, poweroff-bypass, poweron-bypass, vlan-filter, wildcard-vlan*

        Examples:
        ---------\n
        >>> init_variable.confdb_system_virtualwirepair(adom="ADOM Name", name="Virtual Wire Pair Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                member	[...]
                name	[...]
                outer-vlan-id	[...]
                poweroff-bypass	[...]
                poweron-bypass	[...]
                vlan-filter	[...]
                wildcard-vlan	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/virtual-wire-pair/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/system/virtual-wire-pair", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/virtual-wire-pair/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/system/virtual-wire-pair", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_system_virtualwirepair.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_system_virtualwirepair.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_adgrp(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_adgrp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/adgrp*
            */pm/config/global/obj/user/adgrp/{adgrp}*
            */pm/config/adom/{adom}/obj/user/adgrp*
            */pm/config/adom/{adom}/obj/user/adgrp/{adgrp}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *connector-source, id, name, server-name*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_adgrp(adom="ADOM Name", name="AD Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                connector-source	[...]
                id	[...]
                name	[...]
                server-name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/adgrp/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/adgrp", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/adgrp/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/adgrp", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_adgrp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_adgrp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_fortitoken(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_fortitoken\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/fortitoken*
            */pm/config/global/obj/user/fortitoken/{user}*
            */pm/config/adom/{adom}/obj/user/fortitoken*
            */pm/config/adom/{adom}/obj/user/fortitoken/{user}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comments, license, serial-number, status*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_fortitoken(adom="ADOM Name", name="User Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comments	[...]
                license	[...]
                serial-number	[...]
                status	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/fortitoken/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/fortitoken", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/fortitoken/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/fortitoken", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_fortitoken.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_fortitoken.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_fsso(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_fsso\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/fsso*
            */pm/config/global/obj/user/fsso/{connector}*
            */pm/config/adom/{adom}/obj/user/fsso*
            */pm/config/adom/{adom}/obj/user/fsso/{connector}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *_gui_meta, group-poll-interval, interface, interface-select-method, ldap-poll, ldap-poll-filter, ldap-poll-interval, ldap-server, logon-timeout, name, password, password2, password3, password4, password5, port, port2, port3, port4, port5, server, server2, server3, server4, server5, sni, source-ip, source-ip6, ssl, ssl-server-host-ip-check, ssl-trusted-cert, type, user-info-server*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_fsso(adom="ADOM Name", name="FSSO Connector Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                _gui_meta	[...]
                dynamic_mapping	[{
                    _gui_meta	[...]
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    group-poll-interval	[...]
                    interface	[...]
                    interface-select-method	[...]
                    ldap-poll	[...]
                    ldap-poll-filter	[...]
                    ldap-poll-interval	[...]
                    ldap-server	[...]
                    logon-timeout	[...]
                    password	[...]
                    password2	[...]
                    password3	[...]
                    password4	[...]
                    password5	[...]
                    port	[...]
                    port2	[...]
                    port3	[...]
                    port4	[...]
                    port5	[...]
                    server	[...]
                    server2	[...]
                    server3	[...]
                    server4	[...]
                    server5	[...]
                    sni	[...]
                    source-ip	[...]
                    source-ip6	[...]
                    ssl	[...]
                    ssl-server-host-ip-check	[...]
                    ssl-trusted-cert	[...]
                    type	[...]
                    user-info-server	[...]
                }]
                group-poll-interval	[...]
                interface	[...]
                interface-select-method	[...]
                ldap-poll	[...]
                ldap-poll-filter	[...]
                ldap-poll-interval	[...]
                ldap-server	[...]
                logon-timeout	[...]
                name	[...]
                password	[...]
                password2	[...]
                password3	[...]
                password4	[...]
                password5	[...]
                port	[...]
                port2	[...]
                port3	[...]
                port4	[...]
                port5	[...]
                server	[...]
                server2	[...]
                server3	[...]
                server4	[...]
                server5	[...]
                sni	[...]
                source-ip	[...]
                source-ip6	[...]
                ssl	[...]
                ssl-server-host-ip-check	[...]
                ssl-trusted-cert	[...]
                type	[...]
                user-info-server	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/fsso/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/fsso", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/fsso/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/fsso", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_fsso.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_fsso.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_fssopolling(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_fssopolling\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/fsso-polling*
            */pm/config/global/obj/user/fsso-polling/{connector}*
            */pm/config/adom/{adom}/obj/user/fsso-polling*
            */pm/config/adom/{adom}/obj/user/fsso-polling/{connector}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *_gui_meta, default-domain, id, ldap-server, logon-history, password, polling-frequency, port, server, smb-ntlmv1-auth, smbv1, status, user*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_fssopolling(adom="ADOM Name", name="FSSO Connector Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                _gui_meta	[...]
                adgrp	[{
                    name	[...]
                }]
                default-domain	[...]
                id	[...]
                ldap-server	[...]
                logon-history	[...]
                password	[...]
                polling-frequency	[...]
                port	[...]
                server	[...]
                smb-ntlmv1-auth	[...]
                smbv1	[...]
                status	[...]
                user	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/fsso-polling/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/fsso-polling", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/fsso-polling/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/fsso-polling", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_fssopolling.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_fssopolling.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_grp(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/group*
            */pm/config/global/obj/user/group/{group}*
            */pm/config/adom/{adom}/obj/user/group*
            */pm/config/adom/{adom}/obj/user/group/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *auth-concurrent-override, auth-concurrent-value, authtimeout, company, email, expire, expire-type, group-type, http-digest-realm, id, max-accounts, member, mobile-phone, multiple-guest-add, name, password, sms-custom-server, sms-server, sponsor, sso-attribute-value, user-id, user-name*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_grp(adom="ADOM Name", name="User Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                auth-concurrent-override	[...]
                auth-concurrent-value	[...]
                authtimeout	[...]
                company	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    auth-concurrent-override	[...]
                    auth-concurrent-value	[...]
                    authtimeout	[...]
                    company	[...]
                    email	[...]
                    expire	[...]
                    expire-type	[...]
                    group-type	[...]
                    guest	[{
                        comment	[...]
                        company	[...]
                        email	[...]
                        expiration	[...]
                        group	[...]
                        id	[...]
                        mobile-phone	[...]
                        name	[...]
                        password	[...]
                        sponsor	[...]
                        user-id	[...]
                    }]
                    http-digest-realm	[...]
                    id	[...]
                    ldap-memberof	[...]
                    logic-type	[...]
                    match	[{
                        _gui_meta	[...]
                        group-name	[...]
                        id	[...]
                        server-name	[...]
                    }]
                    max-accounts	[...]
                    member	[...]
                    mobile-phone	[...]
                    multiple-guest-add	[...]
                    password	[...]
                    redir-url	[...]
                    sms-custom-server	[...]
                    sms-server	[...]
                    sponsor	[...]
                    sslvpn-bookmarks-group	[...]
                    sslvpn-cache-cleaner	[...]
                    sslvpn-client-check	[...]
                    sslvpn-ftp	[...]
                    sslvpn-http	[...]
                    sslvpn-os-check	[...]
                    sslvpn-os-check-list	{
                        action	[...]
                        latest-patch-level	[...]
                        name	[...]
                        tolerance	[...]
                    }
                    sslvpn-portal	[...]
                    sslvpn-portal-heading	[...]
                    sslvpn-rdp	[...]
                    sslvpn-samba	[...]
                    sslvpn-split-tunneling	[...]
                    sslvpn-ssh	[...]
                    sslvpn-telnet	[...]
                    sslvpn-tunnel	[...]
                    sslvpn-tunnel-endip	[...]
                    sslvpn-tunnel-ip-mode	[...]
                    sslvpn-tunnel-startip	[...]
                    sslvpn-virtual-desktop	[...]
                    sslvpn-vnc	[...]
                    sslvpn-webapp	[...]
                    sso-attribute-value	[...]
                    user-id	[...]
                    user-name	[...]
                }]
                email	[...]
                expire	[...]
                expire-type	[...]
                group-type	[...]
                guest	[{
                    comment	[...]
                    company	[...]
                    email	[...]
                    expiration	[...]
                    id	[...]
                    mobile-phone	[...]
                    name	[...]
                    password	[...]
                    sponsor	[...]
                    user-id	[...]
                }]
                http-digest-realm	[...]
                id	[...]
                match	[{
                    _gui_meta	[...]
                    group-name	[...]
                    id	[...]
                    server-name	[...]
                }]
                max-accounts	[...]
                member	[...]
                mobile-phone	[...]
                multiple-guest-add	[...]
                name	[...]
                password	[...]
                sms-custom-server	[...]
                sms-server	[...]
                sponsor	[...]
                sso-attribute-value	[...]
                user-id	[...]
                user-name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/group/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/group/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/group", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_ldap(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_ldap\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/ldap*
            */pm/config/global/obj/user/ldap/{server}*
            */pm/config/adom/{adom}/obj/user/ldap*
            */pm/config/adom/{adom}/obj/user/ldap/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *account-key-cert-field, account-key-filter, account-key-processing, antiphish, ca-cert, client-cert, client-cert-auth, cnid, dn, group-filter, group-member-check, group-object-filter, group-search-base, interface, interface-select-method, member-attr, name, obtain-user-info, password, password-attr, password-expiry-warning, password-renewal, port, search-type, secondary-server, secure, server, server-identity-check, source-ip, source-port, ssl-min-proto-version, status-ttl, tertiary-server, two-factor, two-factor-authentication, two-factor-filter, two-factor-notification, type, user-info-exchange-server, username*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_ldap(adom="ADOM Name", name="LDAP Server Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                account-key-cert-field	[...]
                account-key-filter	[...]
                account-key-processing	[...]
                antiphish	[...]
                ca-cert	[...]
                client-cert	[...]
                client-cert-auth	[...]
                cnid	[...]
                dn	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    account-key-cert-field	[...]
                    account-key-filter	[...]
                    account-key-name	[...]
                    account-key-processing	[...]
                    account-key-upn-san	[...]
                    antiphish	[...]
                    ca-cert	[...]
                    client-cert	[...]
                    client-cert-auth	[...]
                    cnid	[...]
                    dn	[...]
                    filter	[...]
                    group	[...]
                    group-filter	[...]
                    group-member-check	[...]
                    group-object-filter	[...]
                    group-object-search-base	[...]
                    group-search-base	[...]
                    interface	[...]
                    interface-select-method	[...]
                    max-connections	[...]
                    member-attr	[...]
                    obtain-user-info	[...]
                    password	[...]
                    password-attr	[...]
                    password-expiry-warning	[...]
                    password-renewal	[...]
                    port	[...]
                    retrieve-protection-profile	[...]
                    search-type	[...]
                    secondary-server	[...]
                    secure	[...]
                    server	[...]
                    server-identity-check	[...]
                    source-ip	[...]
                    source-port	[...]
                    ssl-max-proto-version	[...]
                    ssl-min-proto-version	[...]
                    status-ttl	[...]
                    tertiary-server	[...]
                    two-factor	[...]
                    two-factor-authentication	[...]
                    two-factor-filter	[...]
                    two-factor-notification	[...]
                    type	[...]
                    user-info-exchange-server	[...]
                    username	[...]
                }]
                group-filter	[...]
                group-member-check	[...]
                group-object-filter	[...]
                group-search-base	[...]
                interface	[...]
                interface-select-method	[...]
                member-attr	[...]
                name	[...]
                obtain-user-info	[...]
                password	[...]
                password-attr	[...]
                password-expiry-warning	[...]
                password-renewal	[...]
                port	[...]
                search-type	[...]
                secondary-server	[...]
                secure	[...]
                server	[...]
                server-identity-check	[...]
                source-ip	[...]
                source-port	[...]
                ssl-min-proto-version	[...]
                status-ttl	[...]
                tertiary-server	[...]
                two-factor	[...]
                two-factor-authentication	[...]
                two-factor-filter	[...]
                two-factor-notification	[...]
                type	[...]
                user-info-exchange-server	[...]
                username	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/ldap/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/ldap", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/ldap/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/ldap", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_ldap.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_ldap.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_local(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_local\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/local*
            */pm/config/global/obj/user/local/{user}*
            */pm/config/adom/{adom}/obj/user/local*
            */pm/config/adom/{adom}/obj/user/local/{user}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *auth-concurrent-override, auth-concurrent-value, authtimeout, email-to, fortitoken, history0, history1, id, ldap-server, name, passwd, passwd-policy, ppk-identity, ppk-secret, qkd-profile, radius-server, sms-custom-server, sms-phone, sms-server, status, tacacs+-server, two-factor, two-factor-authentication, two-factor-notification, type, username-sensitivity, workstation*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_local(adom="ADOM Name", name="User Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                auth-concurrent-override	[...]
                auth-concurrent-value	[...]
                authtimeout	[...]
                email-to	[...]
                fortitoken	[...]
                history0	[...]
                history1	[...]
                id	[...]
                ldap-server	[...]
                name	[...]
                passwd	[...]
                passwd-policy	[...]
                ppk-identity	[...]
                ppk-secret	[...]
                qkd-profile	[...]
                radius-server	[...]
                sms-custom-server	[...]
                sms-phone	[...]
                sms-server	[...]
                status	[...]
                tacacs+-server	[...]
                two-factor	[...]
                two-factor-authentication	[...]
                two-factor-notification	[...]
                type	[...]
                username-sensitivity	[...]
                workstation	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/local/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/local", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/local/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/local", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_local.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_local.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_passwordpolicy(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_passwordpolicy\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/password-policy*
            */pm/config/global/obj/user/password-policy/{password-policy}*
            */pm/config/adom/{adom}/obj/user/password-policy*
            */pm/config/adom/{adom}/obj/user/password-policy/{password-policy}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *expire-days, expire-status, expired-password-renewal, min-change-characters, min-lower-case-letter, min-non-alphanumeric, min-number, min-upper-case-letter, minimum-length, name, reuse-password, warn-days*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_passwordpolicy(adom="ADOM Name", name="Password Policy Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                expire-days	[...]
                expire-status	[...]
                expired-password-renewal	[...]
                min-change-characters	[...]
                min-lower-case-letter	[...]
                min-non-alphanumeric	[...]
                min-number	[...]
                min-upper-case-letter	[...]
                minimum-length	[...]
                name	[...]
                reuse-password	[...]
                warn-days	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/password-policy/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/password-policy", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/password-policy/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/password-policy", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_passwordpolicy.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_passwordpolicy.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_peer(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_peer\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/peer*
            */pm/config/global/obj/user/peer/{user}*
            */pm/config/adom/{adom}/obj/user/peer*
            */pm/config/adom/{adom}/obj/user/peer/{user}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *ca, cn, cn-type, mandatory-ca-verify, mfa-mode, mfa-password, mfa-server, mfa-username, name, ocsp-override-server, passwd, subject, two-factor*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_peer(adom="ADOM Name", name="User Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                ca	[...]
                cn	[...]
                cn-type	[...]
                mandatory-ca-verify	[...]
                mfa-mode	[...]
                mfa-password	[...]
                mfa-server	[...]
                mfa-username	[...]
                name	[...]
                ocsp-override-server	[...]
                passwd	[...]
                subject	[...]
                two-factor	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/peer/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/peer", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/peer/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/peer", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_peer.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_peer.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_peer_grp(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_peer_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/peergrp*
            */pm/config/global/obj/user/peergrp/{group}*
            */pm/config/adom/{adom}/obj/user/peergrp*
            */pm/config/adom/{adom}/obj/user/peergrp/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *member, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_peer_grp(adom="ADOM Name", name="User Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                member	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/peergrp/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/peergrp", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/peergrp/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/peergrp", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_peer_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_peer_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_radius(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_radius\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/radius*
            */pm/config/global/obj/user/radius/{server}*
            */pm/config/adom/{adom}/obj/user/radius*
            */pm/config/adom/{adom}/obj/user/radius/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *account-key-cert-field, account-key-processing, acct-all-servers, acct-interim-interval, all-usergroup, auth-type, ca-cert, call-station-id-type, class, client-cert, delimiter, group-override-attr-type, h3c-compatibility, interface, interface-select-method, mac-case, mac-password-delimiter, mac-username-delimiter, name, nas-id, nas-id-type, nas-ip, password-encoding, password-renewal, radius-coa, radius-port, require-message-authenticator, rsso, rsso-context-timeout, rsso-endpoint-attribute, rsso-endpoint-block-attribute, rsso-ep-one-ip-only, rsso-flush-ip-session, rsso-log-flags, rsso-log-period, rsso-radius-response, rsso-radius-server-port, rsso-secret, rsso-validate-request-secret, secondary-secret, secondary-server, secret, server, server-identity-check, source-ip, sso-attribute, sso-attribute-key, sso-attribute-value-override, status-ttl, switch-controller-acct-fast-framedip-detect, switch-controller-nas-ip-dynamic, switch-controller-service-type, tertiary-secret, tertiary-server, timeout, tls-min-proto-version, transport-protocol, use-management-vdom, username-case-sensitive*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_radius(adom="ADOM Name", name="RADIUS Server Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                account-key-cert-field	[...]
                account-key-processing	[...]
                accounting-server	[{
                    id	[...]
                    interface	[...]
                    interface-select-method	[...]
                    port	[...]
                    secret	[...]
                    server	[...]
                    source-ip	[...]
                    status	[...]
                }]
                acct-all-servers	[...]
                acct-interim-interval	[...]
                all-usergroup	[...]
                auth-type	[...]
                ca-cert	[...]
                call-station-id-type	[...]
                class	[...]
                client-cert	[...]
                delimiter	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    account-key-cert-field	[...]
                    account-key-processing	[...]
                    accounting-server	[{
                        id	[...]
                        interface	[...]
                        interface-select-method	[...]
                        port	[...]
                        secret	[...]
                        server	[...]
                        source-ip	[...]
                        status	[...]
                    }]
                    acct-all-servers	[...]
                    acct-interim-interval	[...]
                    all-usergroup	[...]
                    auth-type	[...]
                    ca-cert	[...]
                    call-station-id-type	[...]
                    class	[...]
                    client-cert	[...]
                    delimiter	[...]
                    dp-carrier-endpoint-attribute	[...]
                    dp-carrier-endpoint-block-attribute	[...]
                    dp-context-timeout	[...]
                    dp-flush-ip-session	[...]
                    dp-hold-time	[...]
                    dp-http-header	[...]
                    dp-http-header-fallback	[...]
                    dp-http-header-status	[...]
                    dp-http-header-suppress	[...]
                    dp-log-dyn_flags	[...]
                    dp-log-period	[...]
                    dp-mem-percent	[...]
                    dp-profile-attribute	[...]
                    dp-profile-attribute-key	[...]
                    dp-radius-response	[...]
                    dp-radius-server-port	[...]
                    dp-secret	[...]
                    dp-validate-request-secret	[...]
                    dynamic-profile	[...]
                    endpoint-translation	[...]
                    ep-carrier-endpoint-convert-hex	[...]
                    ep-carrier-endpoint-header	[...]
                    ep-carrier-endpoint-header-suppress	[...]
                    ep-carrier-endpoint-prefix	[...]
                    ep-carrier-endpoint-prefix-range-max	[...]
                    ep-carrier-endpoint-prefix-range-min	[...]
                    ep-carrier-endpoint-prefix-string	[...]
                    ep-carrier-endpoint-source	[...]
                    ep-ip-header	[...]
                    ep-ip-header-suppress	[...]
                    ep-missing-header-fallback	[...]
                    ep-profile-query-type	[...]
                    group-override-attr-type	[...]
                    h3c-compatibility	[...]
                    interface	[...]
                    interface-select-method	[...]
                    mac-case	[...]
                    mac-password-delimiter	[...]
                    mac-username-delimiter	[...]
                    nas-id	[...]
                    nas-id-type	[...]
                    nas-ip	[...]
                    password-encoding	[...]
                    password-renewal	[...]
                    radius-coa	[...]
                    radius-port	[...]
                    require-message-authenticator	[...]
                    rsso	[...]
                    rsso-context-timeout	[...]
                    rsso-endpoint-attribute	[...]
                    rsso-endpoint-block-attribute	[...]
                    rsso-ep-one-ip-only	[...]
                    rsso-flush-ip-session	[...]
                    rsso-log-flags	[...]
                    rsso-log-period	[...]
                    rsso-radius-response	[...]
                    rsso-radius-server-port	[...]
                    rsso-secret	[...]
                    rsso-validate-request-secret	[...]
                    secondary-secret	[...]
                    secondary-server	[...]
                    secret	[...]
                    server	[...]
                    server-identity-check	[...]
                    source-ip	[...]
                    sso-attribute	[...]
                    sso-attribute-key	[...]
                    sso-attribute-value-override	[...]
                    status-ttl	[...]
                    switch-controller-acct-fast-framedip-detect	[...]
                    switch-controller-nas-ip-dynamic	[...]
                    switch-controller-service-type	[...]
                    tertiary-secret	[...]
                    tertiary-server	[...]
                    timeout	[...]
                    tls-min-proto-version	[...]
                    transport-protocol	[...]
                    use-group-for-profile	[...]
                    use-management-vdom	[...]
                    username-case-sensitive	[...]
                }]
                group-override-attr-type	[...]
                h3c-compatibility	[...]
                interface	[...]
                interface-select-method	[...]
                mac-case	[...]
                mac-password-delimiter	[...]
                mac-username-delimiter	[...]
                name	[...]
                nas-id	[...]
                nas-id-type	[...]
                nas-ip	[...]
                password-encoding	[...]
                password-renewal	[...]
                radius-coa	[...]
                radius-port	[...]
                require-message-authenticator	[...]
                rsso	[...]
                rsso-context-timeout	[...]
                rsso-endpoint-attribute	[...]
                rsso-endpoint-block-attribute	[...]
                rsso-ep-one-ip-only	[...]
                rsso-flush-ip-session	[...]
                rsso-log-flags	[...]
                rsso-log-period	[...]
                rsso-radius-response	[...]
                rsso-radius-server-port	[...]
                rsso-secret	[...]
                rsso-validate-request-secret	[...]
                secondary-secret	[...]
                secondary-server	[...]
                secret	[...]
                server	[...]
                server-identity-check	[...]
                source-ip	[...]
                sso-attribute	[...]
                sso-attribute-key	[...]
                sso-attribute-value-override	[...]
                status-ttl	[...]
                switch-controller-acct-fast-framedip-detect	[...]
                switch-controller-nas-ip-dynamic	[...]
                switch-controller-service-type	[...]
                tertiary-secret	[...]
                tertiary-server	[...]
                timeout	[...]
                tls-min-proto-version	[...]
                transport-protocol	[...]
                use-management-vdom	[...]
                username-case-sensitive	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/radius/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/radius", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/radius/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/radius", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_radius.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_radius.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_saml(self, adom:str=None, name:str=None, method:str="get", fields:list=None, option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_saml\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/saml*
            */pm/config/global/obj/user/saml/{server}*
            */pm/config/adom/{adom}/obj/user/saml*
            */pm/config/adom/{adom}/obj/user/saml/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *adfs-claim, auth-url, cert, clock-tolerance, digest-method, entity-id, group-claim-type, group-name, idp-cert, idp-entity-id, idp-single-logout-url, idp-single-sign-on-url, limit-relaystate, name, reauth, single-logout-url, single-sign-on-url, user-claim-type, user-name*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_saml(adom="ADOM Name", name="SAML Server Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                adfs-claim	[...]
                auth-url	[...]
                cert	[...]
                clock-tolerance	[...]
                digest-method	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    adfs-claim	[...]
                    auth-url	[...]
                    cert	[...]
                    clock-tolerance	[...]
                    digest-method	[...]
                    entity-id	[...]
                    group-claim-type	[...]
                    group-name	[...]
                    idp-cert	[...]
                    idp-entity-id	[...]
                    idp-single-logout-url	[...]
                    idp-single-sign-on-url	[...]
                    limit-relaystate	[...]
                    reauth	[...]
                    single-logout-url	[...]
                    single-sign-on-url	[...]
                    user-claim-type	[...]
                    user-name	[...]
                }]
                entity-id	[...]
                group-claim-type	[...]
                group-name	[...]
                idp-cert	[...]
                idp-entity-id	[...]
                idp-single-logout-url	[...]
                idp-single-sign-on-url	[...]
                limit-relaystate	[...]
                name	[...]
                reauth	[...]
                single-logout-url	[...]
                single-sign-on-url	[...]
                user-claim-type	[...]
                user-name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/saml/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/saml", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/saml/{name}", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/saml", session=self.session_id, verbose=1, data=data, option=option, fields=fields)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_saml.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_saml.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_user_tacacs(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_user_tacacs\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/user/tacacs+*
            */pm/config/global/obj/user/tacacs+/{server}*
            */pm/config/adom/{adom}/obj/user/tacacs+*
            */pm/config/adom/{adom}/obj/user/tacacs+/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Examples:
        ---------\n
        >>> init_variable.confdb_user_tacacs(adom="ADOM Name", name="TACACS+ Server Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/tacacs+/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/user/tacacs+", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/tacacs+/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/user/tacacs+", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_user_tacacs.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_user_tacacs.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_authentication_scheme(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_authentication_scheme\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/authentication/scheme*
            */pm/config/global/obj/authentication/scheme/{scheme}*
            */pm/config/adom/{adom}/obj/authentication/scheme*
            */pm/config/adom/{adom}/obj/authentication/scheme/{scheme}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *domain-controller, fsso-agent-for-ntlm, fsso-guest, kerberos-keytab, method, name, negotiate-ntlm, require-tfa, saml-server, saml-timeout, ssh-ca, user-cert, user-database*

        Examples:
        ---------\n
        >>> init_variable.confdb_authentication_scheme(adom="ADOM Name", name="Auth Scheme Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                domain-controller	[...]
                fsso-agent-for-ntlm	[...]
                fsso-guest	[...]
                kerberos-keytab	[...]
                method	[...]
                name	[...]
                negotiate-ntlm	[...]
                require-tfa	[...]
                saml-server	[...]
                saml-timeout	[...]
                ssh-ca	[...]
                user-cert	[...]
                user-database	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/authentication/scheme/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/authentication/scheme", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/authentication/scheme/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/authentication/scheme", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_authentication_scheme.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_authentication_scheme.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_casb_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_casb_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/casb/profile*
            */pm/config/global/obj/casb/profile/{profile}*
            */pm/config/adom/{adom}/obj/casb/profile*
            */pm/config/adom/{adom}/obj/casb/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone, move*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_casb_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                name	[...]
                saas-application	[{
                    access-rule	[{
                        action	[...]
                        bypass	[...]
                        name	[...]
                    }]
                    custom-control	[{
                        name	[...]
                        option	[...]
                    }]
                    domain-control	[...]
                    domain-control-domains	[...]
                    log	[...]
                    name	[...]
                    safe-search	[...]
                    safe-search-control	[...]
                    status	[...]
                    tenant-control	[...]
                    tenant-control-tenants	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/casb/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/casb/profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/casb/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/casb/profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_casb_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_casb_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_casb_saasapplication(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_casb_saasapplication\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/casb/saas-application*
            */pm/config/global/obj/casb/saas-application/{saas-application}*
            */pm/config/adom/{adom}/obj/casb/saas-application*
            */pm/config/adom/{adom}/obj/casb/saas-application/{saas-application}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone, move*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *casb-name, description, domains, name, status, type, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_casb_saasapplication(adom="ADOM Name", name="Application Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                casb-name	[...]
                description	[...]
                domains	[...]
                name	[...]
                status	[...]
                type	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/casb/saas-application/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/casb/saas-application", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/casb/saas-application/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/casb/saas-application", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_casb_saasapplication.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_casb_saasapplication.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_casb_useractivity(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_casb_useractivity\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/casb/user-activity*
            */pm/config/global/obj/casb/user-activity/{user-activity}*
            */pm/config/adom/{adom}/obj/casb/user-activity*
            */pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone, move*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *application, casb-name, category, description, match-strategy, name, status, type, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_casb_useractivity(adom="ADOM Name", name="Activity Signature Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                application	[...]
                casb-name	[...]
                category	[...]
                control-options	[{
                    name	[...]
                    operations	[{
                        action	[...]
                        case-sensitive	[...]
                        direction	[...]
                        header-name	[...]
                        name	[...]
                        search-key	[...]
                        search-pattern	[...]
                        target	[...]
                        value-from-input	[...]
                        values	[...]
                    }]
                    status	[...]
                }]
                description	[...]
                match	[{
                    id	[...]
                    rules	[{
                        case-sensitive	[...]
                        domains	[...]
                        header-name	[...]
                        id	[...]
                        match-pattern	[...]
                        match-value	[...]
                        methods	[...]
                        negate	[...]
                        type	[...]
                    }]
                    strategy	[...]
                }]
                match-strategy	[...]
                name	[...]
                status	[...]
                type	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/casb/user-activity/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/casb/user-activity", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/casb/user-activity/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/casb/user-activity", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_casb_useractivity.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_casb_useractivity.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_certificate_template(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_certificate_template\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/certificate/template*
            */pm/config/global/obj/certificate/template/{template}*
            */pm/config/adom/{adom}/obj/certificate/template*
            */pm/config/adom/{adom}/obj/certificate/template/{template}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *city, country, curve-name, digest-type, email, id-type, key-size, key-type, name, organization, organization-unit, scep-ca-identifier, scep-password, scep-server, state, subject-alt-name, subject-name, type*

        Examples:
        ---------\n
        >>> init_variable.confdb_certificate_template(adom="ADOM Name", name="Template Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                city	[...]
                country	[...]
                curve-name	[...]
                digest-type	[...]
                email	[...]
                id-type	[...]
                key-size	[...]
                key-type	[...]
                name	[...]
                organization	[...]
                organization-unit	[...]
                scep-ca-identifier	[...]
                scep-password	[...]
                scep-server	[...]
                state	[...]
                subject-alt-name	[...]
                subject-name	[...]
                type	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/certificate/template/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/certificate/template", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/certificate/template/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/certificate/template", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_certificate_template.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_certificate_template.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_cli_template(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_cli_template\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/cli/template*
            */pm/config/global/obj/cli/template/{template}*
            */pm/config/adom/{adom}/obj/cli/template*
            */pm/config/adom/{adom}/obj/cli/template/{template}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *description, name, position, provision, script, type, variables*

        Examples:
        ---------\n
        >>> init_variable.confdb_cli_template(adom="ADOM Name", name="Template Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                description	[...]
                name	[...]
                position	[...]
                provision	[...]
                script	[...]
                type	[...]
                variables	[...]
                scope member	[{
                    name	[...]
                    vdom	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/cli/template/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/cli/template", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/cli/template/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/cli/template", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_cli_template.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_cli_template.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_cli_template_grp(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_cli_template_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/cli/template-group*
            */pm/config/global/obj/cli/template-group/{group}*
            */pm/config/adom/{adom}/obj/cli/template-group*
            */pm/config/adom/{adom}/obj/cli/template-group/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *description, member, name, variables*

        Examples:
        ---------\n
        >>> init_variable.confdb_cli_template_grp(adom="ADOM Name", name="Template Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                description	[...]
                member	[...]
                name	[...]
                variables	[...]
                scope member	[{
                    name	[...]
                    vdom	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/cli/template-group/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/cli/template-group", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/cli/template-group/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/cli/template-group", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_cli_template_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_cli_template_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_diameterfilter_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_diameterfilter_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/diameter-filter/profile*
            */pm/config/global/obj/diameter-filter/profile/{profile}*
            */pm/config/adom/{adom}/obj/diameter-filter/profile*
            */pm/config/adom/{adom}/obj/diameter-filter/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *cmd-flags-reserve-set, command-code-invalid, command-code-range, comment, log-packet, message-length-invalid, missing-request-action, monitor-all-messages, name, protocol-version-invalid, request-error-flag-set, track-requests-answers*

        Examples:
        ---------\n
        >>> init_variable.confdb_diameterfilter_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                cmd-flags-reserve-set	[...]
                command-code-invalid	[...]
                command-code-range	[...]
                comment	[...]
                log-packet	[...]
                message-length-invalid	[...]
                missing-request-action	[...]
                monitor-all-messages	[...]
                name	[...]
                protocol-version-invalid	[...]
                request-error-flag-set	[...]
                track-requests-answers	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/diameter-filter/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/diameter-filter/profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/diameter-filter/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/diameter-filter/profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_diameterfilter_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_diameterfilter_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dlp_datatype(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dlp_datatype\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dlp/data-type*
            */pm/config/global/obj/dlp/data-type/{data-type}*
            */pm/config/adom/{adom}/obj/dlp/data-type*
            */pm/config/adom/{adom}/obj/dlp/data-type/{data-type}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, look-ahead, look-back, match-ahead, match-around, match-back, name, pattern, transform, verify, verify-transformed-pattern, verify2*

        Examples:
        ---------\n
        >>> init_variable.confdb_dlp_datatype(adom="ADOM Name", name="Data Type Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                look-ahead	[...]
                look-back	[...]
                match-ahead	[...]
                match-around	[...]
                match-back	[...]
                name	[...]
                pattern	[...]
                transform	[...]
                verify	[...]
                verify-transformed-pattern	[...]
                verify2	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/data-type/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/data-type", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/data-type/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/data-type", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dlp_datatype.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dlp_datatype.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dlp_dictionary(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dlp_dictionary\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dlp/dictionary*
            */pm/config/global/obj/dlp/dictionary/{dictionary}*
            */pm/config/adom/{adom}/obj/dlp/dictionary*
            */pm/config/adom/{adom}/obj/dlp/dictionary/{dictionary}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, match-around, match-type, name, uuid*

        Examples:
        ---------\n
        >>> init_variable.confdb_dlp_dictionary(adom="ADOM Name", name="Dictionary Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                entries	[{
                    comment	[...]
                    id	[...]
                    ignore-case	[...]
                    pattern	[...]
                    repeat	[...]
                    status	[...]
                    type	[...]
                }]
                match-around	[...]
                match-type	[...]
                name	[...]
                uuid	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/dictionary/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/dictionary", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/dictionary/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/dictionary", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dlp_dictionary.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dlp_dictionary.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dlp_exactdatamatch(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dlp_exactdatamatch\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dlp/exact-data-match*
            */pm/config/global/obj/dlp/exact-data-match/{template}*
            */pm/config/adom/{adom}/obj/dlp/exact-data-match*
            */pm/config/adom/{adom}/obj/dlp/exact-data-match/{template}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *data, name, optional*

        Examples:
        ---------\n
        >>> init_variable.confdb_dlp_exactdatamatch(adom="ADOM Name", name="Template Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                columns	[{
                    index	[...]
                    optional	[...]
                    type	[...]
                }]
                data	[...]
                name	[...]
                optional	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/exact-data-match/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/exact-data-match", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/exact-data-match/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/exact-data-match", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dlp_exactdatamatch.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dlp_exactdatamatch.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dlp_filepattern(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dlp_filepattern\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dlp/filepattern*
            */pm/config/global/obj/dlp/filepattern/{pattern}*
            */pm/config/adom/{adom}/obj/dlp/filepattern*
            */pm/config/adom/{adom}/obj/dlp/filepattern/{pattern}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, id, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_dlp_filepattern(adom="ADOM Name", name="Pattern Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                entries	[{
                    file-type	[...]
                    filter-type	[...]
                    pattern	[...]
                }]
                id	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/filepattern/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/filepattern", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/filepattern/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/filepattern", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dlp_filepattern.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dlp_filepattern.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dlp_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dlp_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dlp/profile*
            */pm/config/global/obj/dlp/profile/{profile}*
            */pm/config/adom/{adom}/obj/dlp/profile*
            */pm/config/adom/{adom}/obj/dlp/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, dlp-log, extended-log, feature-set, full-archive-proto, nac-quar-log, name, replacemsg-group, summary-proto*

        Examples:
        ---------\n
        >>> init_variable.confdb_dlp_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                dlp-log	[...]
                extended-log	[...]
                feature-set	[...]
                full-archive-proto	[...]
                nac-quar-log	[...]
                name	[...]
                replacemsg-group	[...]
                rule	[{
                    action	[...]
                    archive	[...]
                    expiry	[...]
                    file-size	[...]
                    file-type	[...]
                    filter-by	[...]
                    id	[...]
                    label	[...]
                    match-percentage	[...]
                    name	[...]
                    proto	[...]
                    sensitivity	[...]
                    sensor	[...]
                    severity	[...]
                    type	[...]
                }]
                summary-proto	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dlp_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dlp_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dlp_sensitivity(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dlp_sensitivity\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dlp/sensitivity*
            */pm/config/global/obj/dlp/sensitivity/{setting}*
            */pm/config/adom/{adom}/obj/dlp/sensitivity*
            */pm/config/adom/{adom}/obj/dlp/sensitivity/{setting}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *name*

        Examples:
        ---------\n
        >>> init_variable.confdb_dlp_sensitivity(adom="ADOM Name", name="Setting Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/sensitivity/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/sensitivity", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/sensitivity/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/sensitivity", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dlp_sensitivity.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dlp_sensitivity.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dlp_sensor(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dlp_sensor\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dlp/sensor*
            */pm/config/global/obj/dlp/sensor/{sensor}*
            */pm/config/adom/{adom}/obj/dlp/sensor*
            */pm/config/adom/{adom}/obj/dlp/sensor/{sensor}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, eval, match-type, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_dlp_sensor(adom="ADOM Name", name="Sensor Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                entries	[{
                    count	[...]
                    dictionary	[...]
                    id	[...]
                    status	[...]
                }]
                eval	[...]
                match-type	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/sensor/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dlp/sensor", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/sensor/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dlp/sensor", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dlp_sensor.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dlp_sensor.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dynamic_address(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dynamic_address\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dynamic/address*
            */pm/config/global/obj/dynamic/address/{address}*
            */pm/config/adom/{adom}/obj/dynamic/address*
            */pm/config/adom/{adom}/obj/dynamic/address/{address}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *default, description, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_dynamic_address(adom="ADOM Name", name="Address Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                default	[...]
                description	[...]
                dynamic_addr_mapping	[{
                    addr	[...]
                    id	[...]
                }]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/address/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/address", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/address/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/address", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dynamic_address.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dynamic_address.__name__, msg=f"Login state is {self.loginstate}")
        return response

    def confdb_dynamic_certificate_local(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dynamic_certificate_local\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dynamic/certificate/local*
            */pm/config/global/obj/dynamic/certificate/local/{certificate}*
            */pm/config/adom/{adom}/obj/dynamic/certificate/local*
            */pm/config/adom/{adom}/obj/dynamic/certificate/local/{certificate}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *description, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_dynamic_certificate_local(adom="ADOM Name", name="Certificate Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                description	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    local-cert	[...]
                }]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/certificate/local/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/certificate/local", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/certificate/local/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/certificate/local", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dynamic_certificate_local.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dynamic_certificate_local.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dynamic_interface(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dynamic_interface\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dynamic/interface*
            */pm/config/global/obj/dynamic/interface/{interface}*
            */pm/config/adom/{adom}/obj/dynamic/interface*
            */pm/config/adom/{adom}/obj/dynamic/interface/{interface}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *color, default-mapping, defmap-intf, defmap-intrazone-deny, defmap-zonemember, description, egress-shaping-profile, ingress-shaping-profile, name, single-intf, wildcard, wildcard-intf, zone-only*

        Examples:
        ---------\n
        >>> init_variable.confdb_dynamic_interface(adom="ADOM Name", name="Interface Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                color	[...]
                default-mapping	[...]
                defmap-intf	[...]
                defmap-intrazone-deny	[...]
                defmap-zonemember	[...]
                description	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    egress-shaping-profile	[...]
                    ingress-shaping-profile	[...]
                    intrazone-deny	[...]
                    local-intf	[...]
                }]
                egress-shaping-profile	[...]
                ingress-shaping-profile	[...]
                name	[...]
                platform_mapping	[{
                    egress-shaping-profile	[...]
                    intf-zone	[...]
                    intrazone-deny	[...]
                    name	[...]
                }]
                single-intf	[...]
                wildcard	[...]
                wildcard-intf	[...]
                zone-only	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/interface/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/interface", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/interface/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/interface", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dynamic_interface.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dynamic_interface.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dynamic_ippool(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dynamic_ippool\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dynamic/ippool*
            */pm/config/global/obj/dynamic/ippool/{ippool}*
            */pm/config/adom/{adom}/obj/dynamic/ippool*
            */pm/config/adom/{adom}/obj/dynamic/ippool/{ippool}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *description, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_dynamic_ippool(adom="ADOM Name", name="IP Pool Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                description	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/ippool/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/ippool", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/ippool/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/ippool", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dynamic_ippool.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dynamic_ippool.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dynamic_log_npuserver_grp(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dynamic_log_npuserver_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dynamic/log/npu-server/server-group*
            */pm/config/global/obj/dynamic/log/npu-server/server-group/{group}*
            */pm/config/adom/{adom}/obj/dynamic/log/npu-server/server-group*
            */pm/config/adom/{adom}/obj/dynamic/log/npu-server/server-group/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *description, group-name*

        Examples:
        ---------\n
        >>> init_variable.confdb_dynamic_log_npuserver_grp(adom="ADOM Name", name="Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                description	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    group-name	[...]
                }]
                group-name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/log/npu-server/server-group/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/log/npu-server/server-group", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/log/npu-server/server-group/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/log/npu-server/server-group", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dynamic_log_npuserver_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dynamic_log_npuserver_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dynamic_multicast_interface(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dynamic_multicast_interface\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dynamic/multicast/interface*
            */pm/config/global/obj/dynamic/multicast/interface/{interface}*
            */pm/config/adom/{adom}/obj/dynamic/multicast/interface*
            */pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *default-mapping, defmap-intf, description, name, zone-only*

        Examples:
        ---------\n
        >>> init_variable.confdb_dynamic_multicast_interface(adom="ADOM Name", name="Interface Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                default-mapping	[...]
                defmap-intf	[...]
                description	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    local-intf	[...]
                }]
                name	[...]
                zone-only	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/multicast/interface", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/multicast/interface/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/multicast/interface", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dynamic_multicast_interface.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dynamic_multicast_interface.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dynamic_vip(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dynamic_vip\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dynamic/vip*
            */pm/config/global/obj/dynamic/vip/{vip}*
            */pm/config/adom/{adom}/obj/dynamic/vip*
            */pm/config/adom/{adom}/obj/dynamic/vip/{vip}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *description, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_dynamic_vip(adom="ADOM Name", name="Virtual IP Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                description	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/vip/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/vip", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/vip/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/vip", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dynamic_vip.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dynamic_vip.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_dynamic_vpntunnel(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_dynamic_vpntunnel\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/dynamic/vpntunnel*
            */pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}*
            */pm/config/adom/{adom}/obj/dynamic/vpntunnel*
            */pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *description, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_dynamic_vpntunnel(adom="ADOM Name", name="VPN Tunnel Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                description	[...]
                dynamic_mapping	[{
                    _scope	[{
                        name	[...]
                        vdom	[...]
                    }]
                    local-ipsec	[...]
                }]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/dynamic/vpntunnel", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/vpntunnel/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/dynamic/vpntunnel", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_dynamic_vpntunnel.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_dynamic_vpntunnel.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_endpointctrl_fctems(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_endpointctrl_fctems\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/endpoint-control/fctems*
            */pm/config/global/obj/endpoint-control/fctems/{server}*
            */pm/config/adom/{adom}/obj/endpoint-control/fctems*
            */pm/config/adom/{adom}/obj/endpoint-control/fctems/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *call-timeout, capabilities, certificate-fingerprint, cloud-authentication-access-key, dirty-reason, ems-id, fortinetone-cloud-authentication, https-port, interface, interface-select-method, name, out-of-sync-threshold, preserve-ssl-session, pull-avatars, pull-malware-hash, pull-sysinfo, pull-tags, pull-vulnerabilities, send-tags-to-all-vdoms, serial-number, server, source-ip, status, tenant-id, trust-ca-cn, verified-cn, verifying-ca, websocket-override*

        Examples:
        ---------\n
        >>> init_variable.confdb_endpointctrl_fctems(adom="ADOM Name", name="EMS Server Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                call-timeout	[...]
                capabilities	[...]
                certificate-fingerprint	[...]
                cloud-authentication-access-key	[...]
                dirty-reason	[...]
                ems-id	[...]
                fortinetone-cloud-authentication	[...]
                https-port	[...]
                interface	[...]
                interface-select-method	[...]
                name	[...]
                out-of-sync-threshold	[...]
                preserve-ssl-session	[...]
                pull-avatars	[...]
                pull-malware-hash	[...]
                pull-sysinfo	[...]
                pull-tags	[...]
                pull-vulnerabilities	[...]
                send-tags-to-all-vdoms	[...]
                serial-number	[...]
                server	[...]
                source-ip	[...]
                status	[...]
                tenant-id	[...]
                trust-ca-cn	[...]
                verified-cn	[...]
                verifying-ca	[...]
                websocket-override	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/endpoint-control/fctems/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/endpoint-control/fctems", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/endpoint-control/fctems/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/endpoint-control/fctems", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_endpointctrl_fctems.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_endpointctrl_fctems.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_extenderctrl_simprofile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_extenderctrl_simprofile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/extender-controller/sim_profile*
            */pm/config/global/obj/extender-controller/sim_profile/{profile}*
            */pm/config/adom/{adom}/obj/extender-controller/sim_profile*
            */pm/config/adom/{adom}/obj/extender-controller/sim_profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *conn-status, default-sim, description, gps, modem-id, name, preferred-carrier, redundant-intf, redundant-mode, sim1-pin, sim1-pin-code, sim2-pin, sim2-pin-code, status*

        Examples:
        ---------\n
        >>> init_variable.confdb_extenderctrl_simprofile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                auto-switch_profile	{
                    dataplan	[...]
                    disconnect	[...]
                    disconnect-period	[...]
                    disconnect-threshold	[...]
                    signal	[...]
                    status	[...]
                    switch-back	[...]
                    switch-back-time	[...]
                    switch-back-timer	[...]
                }
                conn-status	[...]
                default-sim	[...]
                description	[...]
                gps	[...]
                modem-id	[...]
                name	[...]
                preferred-carrier	[...]
                redundant-intf	[...]
                redundant-mode	[...]
                sim1-pin	[...]
                sim1-pin-code	[...]
                sim2-pin	[...]
                sim2-pin-code	[...]
                status	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/extender-controller/sim_profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/extender-controller/sim_profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/extender-controller/sim_profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/extender-controller/sim_profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_extenderctrl_simprofile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_extenderctrl_simprofile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_extenderctrl_template(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_extenderctrl_template\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/extender-controller/template*
            */pm/config/global/obj/extender-controller/template/{template}*
            */pm/config/adom/{adom}/obj/extender-controller/template*
            */pm/config/adom/{adom}/obj/extender-controller/template/{template}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *dataplan, description, modem1_ifname, modem1_sim_profile, modem2_ifname, modem2_sim_profile, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_extenderctrl_template(adom="ADOM Name", name="Template Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                dataplan	[...]
                description	[...]
                modem1_ifname	[...]
                modem1_sim_profile	[...]
                modem2_ifname	[...]
                modem2_sim_profile	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/extender-controller/template/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/extender-controller/template", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/extender-controller/template/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/extender-controller/template", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_extenderctrl_template.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_extenderctrl_template.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_extensionctrl_dataplan(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_extensionctrl_dataplan\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/extension-controller/dataplan*
            */pm/config/global/obj/extension-controller/dataplan/{dataplan}*
            */pm/config/adom/{adom}/obj/extension-controller/dataplan*
            */pm/config/adom/{adom}/obj/extension-controller/dataplan/{dataplan}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *apn, auth-type, billing-date, capacity, carrier, iccid, modem-id, monthly-fee, name, overage, password, pdn, preferred-subnet, private-network, signal-period, signal-threshold, slot, type, username*

        Examples:
        ---------\n
        >>> init_variable.confdb_extensionctrl_dataplan(adom="ADOM Name", name="Data Plan Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                apn	[...]
                auth-type	[...]
                billing-date	[...]
                capacity	[...]
                carrier	[...]
                iccid	[...]
                modem-id	[...]
                monthly-fee	[...]
                name	[...]
                overage	[...]
                password	[...]
                pdn	[...]
                preferred-subnet	[...]
                private-network	[...]
                signal-period	[...]
                signal-threshold	[...]
                slot	[...]
                type	[...]
                username	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/extension-controller/dataplan/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/extension-controller/dataplan", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/extension-controller/dataplan/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/extension-controller/dataplan", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_extensionctrl_dataplan.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_extensionctrl_dataplan.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_extensionctrl_extenderprofile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_extensionctrl_extenderprofile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/extension-controller/extender-profile*
            */pm/config/global/obj/extension-controller/extender-profile/{profile}*
            */pm/config/adom/{adom}/obj/extension-controller/extender-profile*
            */pm/config/adom/{adom}/obj/extension-controller/extender-profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *_is_factory_setting, allowaccess, bandwidth-limit, enforce-bandwidth, extension, id, login-password, login-password-change, model, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_extensionctrl_extenderprofile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                _is_factory_setting	[...]
                allowaccess	[...]
                bandwidth-limit	[...]
                cellular	{
                    controller-report	{
                        interval	[...]
                        signal-threshold	[...]
                        status	[...]
                    }
                    dataplan	[...]
                    modem1	{
                        auto-switch	{
                            dataplan	[...]
                            disconnect	[...]
                            disconnect-period	[...]
                            disconnect-threshold	[...]
                            signal	[...]
                            switch-back	[...]
                            switch-back-time	[...]
                            switch-back-timer	[...]
                        }
                        conn-status	[...]
                        default-sim	[...]
                        gps	[...]
                        modem-id	[...]
                        preferred-carrier	[...]
                        redundant-intf	[...]
                        redundant-mode	[...]
                        sim1-pin	[...]
                        sim1-pin-code	[...]
                        sim2-pin	[...]
                        sim2-pin-code	[...]
                    }
                    modem2	{
                        auto-switch	{
                            dataplan	[...]
                            disconnect	[...]
                            disconnect-period	[...]
                            disconnect-threshold	[...]
                            signal	[...]
                            switch-back	[...]
                            switch-back-time	[...]
                            switch-back-timer	[...]
                        }
                        conn-status	[...]
                        default-sim	[...]
                        gps	[...]
                        modem-id	[...]
                        preferred-carrier	[...]
                        redundant-intf	[...]
                        redundant-mode	[...]
                        sim1-pin	[...]
                        sim1-pin-code	[...]
                        sim2-pin	[...]
                        sim2-pin-code	[...]
                    }
                    sms-notification	{
                        alert	{
                            data-exhausted	[...]
                            fgt-backup-mode-switch	[...]
                            low-signal-strength	[...]
                            mode-switch	[...]
                            os-image-fallback	[...]
                            session-disconnect	[...]
                            system-reboot	[...]
                        }
                        receiver	[{
                            alert	[...]
                            name	[...]
                            phone-number	[...]
                            status	[...]
                        }]
                        status	[...]
                    }
                }
                enforce-bandwidth	[...]
                extension	[...]
                id	[...]
                lan-extension	{
                    backhaul	[{
                        name	[...]
                        port	[...]
                        role	[...]
                        weight	[...]
                    }]
                    backhaul-interface	[...]
                    backhaul-ip	[...]
                    ipsec-tunnel	[...]
                    link-loadbalance	[...]
                }
                login-password	[...]
                login-password-change	[...]
                model	[...]
                name	[...]
                wifi	{
                    DFS	[...]
                    country	[...]
                    radio-1	{
                        80211d	[...]
                        band	[...]
                        bandwidth	[...]
                        beacon-interval	[...]
                        bss-color	[...]
                        bss-color-mode	[...]
                        channel	[...]
                        extension-channel	[...]
                        guard-interval	[...]
                        lan-ext-vap	[...]
                        local-vaps	[...]
                        max-clients	[...]
                        mode	[...]
                        operating-standard	[...]
                        power-level	[...]
                        radio-id	[...]
                        status	[...]
                    }
                    radio-2	{
                        80211d	[...]
                        band	[...]
                        bandwidth	[...]
                        beacon-interval	[...]
                        bss-color	[...]
                        bss-color-mode	[...]
                        channel	[...]
                        extension-channel	[...]
                        guard-interval	[...]
                        lan-ext-vap	[...]
                        local-vaps	[...]
                        max-clients	[...]
                        mode	[...]
                        operating-standard	[...]
                        power-level	[...]
                        radio-id	[...]
                        status	[...]
                    }
                }
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/extension-controller/extender-profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/extension-controller/extender-profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/extension-controller/extender-profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_extensionctrl_extenderprofile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_extensionctrl_extenderprofile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_extensionctrl_extendervap(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_extensionctrl_extendervap\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/extension-controller/extender-vap*
            */pm/config/global/obj/extension-controller/extender-vap/{vap}*
            */pm/config/adom/{adom}/obj/extension-controller/extender-vap*
            */pm/config/adom/{adom}/obj/extension-controller/extender-vap/{vap}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *allowaccess, auth-server-address, auth-server-port, auth-server-secret, broadcast-ssid, bss-color-partial, dtim, end-ip, ip-address, max-clients, mu-mimo, name, passphrase, pmf, rts-threshold, sae-password, security, ssid, start-ip, target-wake-time, type*

        Examples:
        ---------\n
        >>> init_variable.confdb_extensionctrl_extendervap(adom="ADOM Name", name="Virtual AP Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                allowaccess	[...]
                auth-server-address	[...]
                auth-server-port	[...]
                auth-server-secret	[...]
                broadcast-ssid	[...]
                bss-color-partial	[...]
                dtim	[...]
                end-ip	[...]
                ip-address	[...]
                max-clients	[...]
                mu-mimo	[...]
                name	[...]
                passphrase	[...]
                pmf	[...]
                rts-threshold	[...]
                sae-password	[...]
                security	[...]
                ssid	[...]
                start-ip	[...]
                target-wake-time	[...]
                type	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/extension-controller/extender-vap/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/extension-controller/extender-vap", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/extension-controller/extender-vap/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/extension-controller/extender-vap", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_extensionctrl_extendervap.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_extensionctrl_extendervap.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_gtp_apn(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_gtp_apn\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/gtp/apn*
            */pm/config/global/obj/gtp/apn/{apn}*
            */pm/config/adom/{adom}/obj/gtp/apn*
            */pm/config/adom/{adom}/obj/gtp/apn/{apn}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *apn, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_gtp_apn(adom="ADOM Name", name="APN Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                apn	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/apn/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/apn", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/apn/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/apn", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_gtp_apn.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_gtp_apn.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_gtp_apn_grp(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_gtp_apn_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/gtp/apngrp*
            */pm/config/global/obj/gtp/apngrp/{group}*
            */pm/config/adom/{adom}/obj/gtp/apngrp*
            */pm/config/adom/{adom}/obj/gtp/apngrp/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *member, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_gtp_apn_grp(adom="ADOM Name", name="APN Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                member	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/apngrp/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/apngrp", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/apngrp/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/apngrp", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_gtp_apn_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_gtp_apn_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_gtp_ieallowlist(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_gtp_ieallowlist\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/gtp/ie-allow-list*
            */pm/config/global/obj/gtp/ie-allow-list/{list}*
            */pm/config/adom/{adom}/obj/gtp/ie-allow-list*
            */pm/config/adom/{adom}/obj/gtp/ie-allow-list/{list}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *name*

        Examples:
        ---------\n
        >>> init_variable.confdb_gtp_ieallowlist(adom="ADOM Name", name="IE Allow List Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                entries	[{
                    id	[...]
                    ie	[...]
                    message	[...]
                }]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/ie-allow-list/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/ie-allow-list", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/ie-allow-list/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/ie-allow-list", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_gtp_ieallowlist.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_gtp_ieallowlist.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_gtp_messagefilter_v0v1(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_gtp_messagefilter_v0v1\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/gtp/message-filter-v0v1*
            */pm/config/global/obj/gtp/message-filter-v0v1/{filter}*
            */pm/config/adom/{adom}/obj/gtp/message-filter-v0v1*
            */pm/config/adom/{adom}/obj/gtp/message-filter-v0v1/{filter}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *create-mbms, create-pdp, data-record, delete-aa-pdp, delete-mbms, delete-pdp, echo, end-marker, error-indication, failure-report, fwd-relocation, fwd-srns-context, gtp-pdu, identification, mbms-de-registration, mbms-notification, mbms-registration, mbms-session-start, mbms-session-stop, mbms-session-update, ms-info-change-notif, name, node-alive, note-ms-present, pdu-notification, ran-info, redirection, relocation-cancel, send-route, sgsn-context, support-extension, ue-registration-query, unknown-message, unknown-message-white-list, update-mbms, update-pdp, v0-create-aa-pdp--v1-init-pdp-ctx, version-not-support*

        Examples:
        ---------\n
        >>> init_variable.confdb_gtp_messagefilter_v0v1(adom="ADOM Name", name="Message Filter Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                create-mbms	[...]
                create-pdp	[...]
                data-record	[...]
                delete-aa-pdp	[...]
                delete-mbms	[...]
                delete-pdp	[...]
                echo	[...]
                end-marker	[...]
                error-indication	[...]
                failure-report	[...]
                fwd-relocation	[...]
                fwd-srns-context	[...]
                gtp-pdu	[...]
                identification	[...]
                mbms-de-registration	[...]
                mbms-notification	[...]
                mbms-registration	[...]
                mbms-session-start	[...]
                mbms-session-stop	[...]
                mbms-session-update	[...]
                ms-info-change-notif	[...]
                name	[...]
                node-alive	[...]
                note-ms-present	[...]
                pdu-notification	[...]
                ran-info	[...]
                redirection	[...]
                relocation-cancel	[...]
                send-route	[...]
                sgsn-context	[...]
                support-extension	[...]
                ue-registration-query	[...]
                unknown-message	[...]
                unknown-message-white-list	[...]
                update-mbms	[...]
                update-pdp	[...]
                v0-create-aa-pdp--v1-init-pdp-ctx	[...]
                version-not-support	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/message-filter-v0v1/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/message-filter-v0v1", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/message-filter-v0v1/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/message-filter-v0v1", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_gtp_messagefilter_v0v1.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_gtp_messagefilter_v0v1.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_gtp_messagefilter_v2(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_gtp_messagefilter_v2\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/gtp/message-filter-v2*
            */pm/config/global/obj/gtp/message-filter-v2/{filter}*
            */pm/config/adom/{adom}/obj/gtp/message-filter-v2*
            */pm/config/adom/{adom}/obj/gtp/message-filter-v2/{filter}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *alert-mme-notif-ack, bearer-resource-cmd-fail, change-notification, configuration-transfer-tunnel, context-req-res-ack, create-bearer, create-forwarding-tunnel-req-resp, create-indirect-forwarding-tunnel-req-resp, create-session, cs-paging, delete-bearer-cmd-fail, delete-bearer-req-resp, delete-indirect-forwarding-tunnel-req-resp, delete-pdn-connection-set, delete-session, detach-notif-ack, dlink-data-notif-ack, dlink-notif-failure, echo, forward-access-notif-ack, forward-relocation-cmp-notif-ack, forward-relocation-req-res, identification-req-resp, isr-status, mbms-session-start-req-resp, mbms-session-stop-req-resp, mbms-session-update-req-resp, modify-access-req-resp, modify-bearer-cmd-fail, modify-bearer-req-resp, name, pgw-dlink-notif-ack, pgw-restart-notif-ack, ran-info-relay, release-access-bearer-req-resp, relocation-cancel-req-resp, remote-ue-report-notif-ack, reserved-for-earlier-version, resume, stop-paging-indication, suspend, trace-session, ue-activity-notif-ack, ue-registration-query-req-resp, unknown-message, unknown-message-white-list, update-bearer, update-pdn-connection-set, version-not-support*

        Examples:
        ---------\n
        >>> init_variable.confdb_gtp_messagefilter_v2(adom="ADOM Name", name="Message Filter Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                alert-mme-notif-ack	[...]
                bearer-resource-cmd-fail	[...]
                change-notification	[...]
                configuration-transfer-tunnel	[...]
                context-req-res-ack	[...]
                create-bearer	[...]
                create-forwarding-tunnel-req-resp	[...]
                create-indirect-forwarding-tunnel-req-resp	[...]
                create-session	[...]
                cs-paging	[...]
                delete-bearer-cmd-fail	[...]
                delete-bearer-req-resp	[...]
                delete-indirect-forwarding-tunnel-req-resp	[...]
                delete-pdn-connection-set	[...]
                delete-session	[...]
                detach-notif-ack	[...]
                dlink-data-notif-ack	[...]
                dlink-notif-failure	[...]
                echo	[...]
                forward-access-notif-ack	[...]
                forward-relocation-cmp-notif-ack	[...]
                forward-relocation-req-res	[...]
                identification-req-resp	[...]
                isr-status	[...]
                mbms-session-start-req-resp	[...]
                mbms-session-stop-req-resp	[...]
                mbms-session-update-req-resp	[...]
                modify-access-req-resp	[...]
                modify-bearer-cmd-fail	[...]
                modify-bearer-req-resp	[...]
                name	[...]
                pgw-dlink-notif-ack	[...]
                pgw-restart-notif-ack	[...]
                ran-info-relay	[...]
                release-access-bearer-req-resp	[...]
                relocation-cancel-req-resp	[...]
                remote-ue-report-notif-ack	[...]
                reserved-for-earlier-version	[...]
                resume	[...]
                stop-paging-indication	[...]
                suspend	[...]
                trace-session	[...]
                ue-activity-notif-ack	[...]
                ue-registration-query-req-resp	[...]
                unknown-message	[...]
                unknown-message-white-list	[...]
                update-bearer	[...]
                update-pdn-connection-set	[...]
                version-not-support	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/message-filter-v2/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/message-filter-v2", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/message-filter-v2/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/message-filter-v2", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_gtp_messagefilter_v2.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_gtp_messagefilter_v2.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_gtp_rattimeout_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_gtp_rattimeout_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/gtp/rat-timeout-profile*
            */pm/config/global/obj/gtp/rat-timeout-profile/{profile}*
            */pm/config/adom/{adom}/obj/gtp/rat-timeout-profile*
            */pm/config/adom/{adom}/obj/gtp/rat-timeout-profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *eutran-timeout, gan-timeout, geran-timeout, hspa-timeout, ltem-timeout, name, nbiot-timeout, nr-timeout, utran-timeout, virtual-timeout, wlan-timeout*

        Examples:
        ---------\n
        >>> init_variable.confdb_gtp_rattimeout_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                eutran-timeout	[...]
                gan-timeout	[...]
                geran-timeout	[...]
                hspa-timeout	[...]
                ltem-timeout	[...]
                name	[...]
                nbiot-timeout	[...]
                nr-timeout	[...]
                utran-timeout	[...]
                virtual-timeout	[...]
                wlan-timeout	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/rat-timeout-profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/rat-timeout-profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/rat-timeout-profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/rat-timeout-profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_gtp_rattimeout_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_gtp_rattimeout_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_gtp_tunnel_limit(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_gtp_tunnel_limit\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/gtp/tunnel-limit*
            */pm/config/global/obj/gtp/tunnel-limit/{limiter}*
            */pm/config/adom/{adom}/obj/gtp/tunnel-limit*
            */pm/config/adom/{adom}/obj/gtp/tunnel-limit/{limiter}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *name, tunnel-limit*

        Examples:
        ---------\n
        >>> init_variable.confdb_gtp_tunnel_limit(adom="ADOM Name", name="Limiter Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                name	[...]
                tunnel-limit	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/tunnel-limit/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/gtp/tunnel-limit", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/tunnel-limit/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/gtp/tunnel-limit", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_gtp_tunnel_limit.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_gtp_tunnel_limit.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_icap_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_icap_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/icap/profile*
            */pm/config/global/obj/icap/profile/{profile}*
            */pm/config/adom/{adom}/obj/icap/profile*
            */pm/config/adom/{adom}/obj/icap/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *204-response, 204-size-limit, chunk-encap, comment, extension-feature, file-transfer, file-transfer-failure, file-transfer-path, file-transfer-server, icap-block-log, methods, name, preview, preview-data-length, replacemsg-group, request, request-failure, request-path, request-server, respmod-default-action, response, response-failure, response-path, response-req-hdr, response-server, scan-progress-interval, streaming-content-bypass, timeout*

        Examples:
        ---------\n
        >>> init_variable.confdb_icap_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                204-response	[...]
                204-size-limit	[...]
                chunk-encap	[...]
                comment	[...]
                extension-feature	[...]
                file-transfer	[...]
                file-transfer-failure	[...]
                file-transfer-path	[...]
                file-transfer-server	[...]
                icap-block-log	[...]
                icap-headers	[{
                    base64-encoding	[...]
                    content	[...]
                    id	[...]
                    name	[...]
                }]
                methods	[...]
                name	[...]
                preview	[...]
                preview-data-length	[...]
                replacemsg-group	[...]
                request	[...]
                request-failure	[...]
                request-path	[...]
                request-server	[...]
                respmod-default-action	[...]
                respmod-forward-rules	[{
                    action	[...]
                    header-group	[{
                        case-sensitivity	[...]
                        header	[...]
                        header-name	[...]
                        id	[...]
                    }]
                    host	[...]
                    http-resp-status-code	[...]
                    name	[...]
                }]
                response	[...]
                response-failure	[...]
                response-path	[...]
                response-req-hdr	[...]
                response-server	[...]
                scan-progress-interval	[...]
                streaming-content-bypass	[...]
                timeout	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/icap/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/icap/profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/icap/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/icap/profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_icap_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_icap_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_icap_server(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_icap_server\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/icap/server*
            */pm/config/global/obj/icap/server/{server}*
            */pm/config/adom/{adom}/obj/icap/server*
            */pm/config/adom/{adom}/obj/icap/server/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *addr-type, fqdn, healthcheck, healthcheck-service, ip-address, ip6-address, max-connections, name, port, secure, ssl-cert*

        Examples:
        ---------\n
        >>> init_variable.confdb_icap_server(adom="ADOM Name", name="ICAP Server Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                addr-type	[...]
                fqdn	[...]
                healthcheck	[...]
                healthcheck-service	[...]
                ip-address	[...]
                ip6-address	[...]
                max-connections	[...]
                name	[...]
                port	[...]
                secure	[...]
                ssl-cert	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/icap/server/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/icap/server", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/icap/server/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/icap/server", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_icap_server.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_icap_server.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_sctpfilter_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_sctpfilter_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/sctp-filter/profile*
            */pm/config/global/obj/sctp-filter/profile/{profile}*
            */pm/config/adom/{adom}/obj/sctp-filter/profile*
            */pm/config/adom/{adom}/obj/sctp-filter/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_sctpfilter_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                name	[...]
                ppid-filters	[{
                    action	[...]
                    comment	[...]
                    id	[...]
                    ppid	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/sctp-filter/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/sctp-filter/profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/sctp-filter/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/sctp-filter/profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_sctpfilter_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_sctpfilter_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_videofilter_keyword(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_videofilter_keyword\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/videofilter/keyword*
            */pm/config/global/obj/videofilter/keyword/{keyword}*
            */pm/config/adom/{adom}/obj/videofilter/keyword*
            */pm/config/adom/{adom}/obj/videofilter/keyword/{keyword}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, id, match, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_videofilter_keyword(adom="ADOM Name", name="Keyword Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                id	[...]
                match	[...]
                name	[...]
                word	[{
                    comment	[...]
                    name	[...]
                    pattern-type	[...]
                    status	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/videofilter/keyword/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/videofilter/keyword", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/videofilter/keyword/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/videofilter/keyword", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_videofilter_keyword.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_videofilter_keyword.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_videofilter_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_videofilter_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/videofilter/profile*
            */pm/config/global/obj/videofilter/profile/{profile}*
            */pm/config/adom/{adom}/obj/videofilter/profile*
            */pm/config/adom/{adom}/obj/videofilter/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, dailymotion, default-action, log, name, replacemsg-group, vimeo, youtube, youtube-channel-filter*

        Examples:
        ---------\n
        >>> init_variable.confdb_videofilter_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                dailymotion	[...]
                default-action	[...]
                filters	[{
                    action	[...]
                    category	[...]
                    channel	[...]
                    comment	[...]
                    id	[...]
                    keyword	[...]
                    log	[...]
                    type	[...]
                }]
                fortiguard-category	{
                    filters	[{
                        action	[...]
                        category-id	[...]
                        id	[...]
                        log	[...]
                    }]
                }
                log	[...]
                name	[...]
                replacemsg-group	[...]
                vimeo	[...]
                youtube	[...]
                youtube-channel-filter	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/videofilter/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/videofilter/profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/videofilter/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/videofilter/profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_videofilter_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_videofilter_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_videofilter_youtube_channelfilter(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_videofilter_youtube_channelfilter\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/videofilter/youtube-channel-filter*
            */pm/config/global/obj/videofilter/youtube-channel-filter/{filter}*
            */pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter*
            */pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{filter}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, id, log, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_videofilter_youtube_channelfilter(adom="ADOM Name", name="Filter ID", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                entries	[{
                    action	[...]
                    channel-id	[...]
                    comment	[...]
                    id	[...]
                }]
                id	[...]
                log	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/videofilter/youtube-channel-filter/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/videofilter/youtube-channel-filter", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_videofilter_youtube_channelfilter.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_videofilter_youtube_channelfilter.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_virtualpatch_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_virtualpatch_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/virtual-patch/profile*
            */pm/config/global/obj/virtual-patch/profile/{profile}*
            */pm/config/adom/{adom}/obj/virtual-patch/profile*
            */pm/config/adom/{adom}/obj/virtual-patch/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *action, comment, log, name, severity*

        Examples:
        ---------\n
        >>> init_variable.confdb_virtualpatch_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                action	[...]
                comment	[...]
                exemption	[{
                    device	[...]
                    id	[...]
                    rule	[...]
                    status	[...]
                }]
                log	[...]
                name	[...]
                severity	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/virtual-patch/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/virtual-patch/profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/virtual-patch/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/virtual-patch/profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_virtualpatch_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_virtualpatch_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_voip_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_voip_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/voip/profile*
            */pm/config/global/obj/voip/profile/{profile}*
            */pm/config/adom/{adom}/obj/voip/profile*
            */pm/config/adom/{adom}/obj/voip/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, feature-set, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_voip_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                feature-set	[...]
                msrp	{
                    log-violations	[...]
                    max-msg-size	[...]
                    max-msg-size-action	[...]
                    status	[...]
                }
                name	[...]
                sccp	{
                    block-mcast	[...]
                    log-call-summary	[...]
                    log-violations	[...]
                    max-calls	[...]
                    status	[...]
                    verify-header	[...]
                }
                sip	{
                    ack-rate	[...]
                    ack-rate-track	[...]
                    block-ack	[...]
                    block-bye	[...]
                    block-cancel	[...]
                    block-geo-red-options	[...]
                    block-info	[...]
                    block-invite	[...]
                    block-long-lines	[...]
                    block-message	[...]
                    block-notify	[...]
                    block-options	[...]
                    block-prack	[...]
                    block-publish	[...]
                    block-refer	[...]
                    block-register	[...]
                    block-subscribe	[...]
                    block-unknown	[...]
                    block-update	[...]
                    bye-rate	[...]
                    bye-rate-track	[...]
                    call-id-regex	[...]
                    call-keepalive	[...]
                    cancel-rate	[...]
                    cancel-rate-track	[...]
                    contact-fixup	[...]
                    content-type-regex	[...]
                    hnt-restrict-source-ip	[...]
                    hosted-nat-traversal	[...]
                    info-rate	[...]
                    info-rate-track	[...]
                    invite-rate	[...]
                    invite-rate-track	[...]
                    ips-rtp	[...]
                    log-call-summary	[...]
                    log-violations	[...]
                    malformed-header-allow	[...]
                    malformed-header-call-id	[...]
                    malformed-header-contact	[...]
                    malformed-header-content-length	[...]
                    malformed-header-content-type	[...]
                    malformed-header-cseq	[...]
                    malformed-header-expires	[...]
                    malformed-header-from	[...]
                    malformed-header-max-forwards	[...]
                    malformed-header-no-proxy-require	[...]
                    malformed-header-no-require	[...]
                    malformed-header-p-asserted-identity	[...]
                    malformed-header-rack	[...]
                    malformed-header-record-route	[...]
                    malformed-header-route	[...]
                    malformed-header-rseq	[...]
                    malformed-header-sdp-a	[...]
                    malformed-header-sdp-b	[...]
                    malformed-header-sdp-c	[...]
                    malformed-header-sdp-i	[...]
                    malformed-header-sdp-k	[...]
                    malformed-header-sdp-m	[...]
                    malformed-header-sdp-o	[...]
                    malformed-header-sdp-r	[...]
                    malformed-header-sdp-s	[...]
                    malformed-header-sdp-t	[...]
                    malformed-header-sdp-v	[...]
                    malformed-header-sdp-z	[...]
                    malformed-header-to	[...]
                    malformed-header-via	[...]
                    malformed-request-line	[...]
                    max-body-length	[...]
                    max-dialogs	[...]
                    max-idle-dialogs	[...]
                    max-line-length	[...]
                    message-rate	[...]
                    message-rate-track	[...]
                    nat-port-range	[...]
                    nat-trace	[...]
                    no-sdp-fixup	[...]
                    notify-rate	[...]
                    notify-rate-track	[...]
                    open-contact-pinhole	[...]
                    open-record-route-pinhole	[...]
                    open-register-pinhole	[...]
                    open-via-pinhole	[...]
                    options-rate	[...]
                    options-rate-track	[...]
                    prack-rate	[...]
                    prack-rate-track	[...]
                    preserve-override	[...]
                    provisional-invite-expiry-time	[...]
                    publish-rate	[...]
                    publish-rate-track	[...]
                    refer-rate	[...]
                    refer-rate-track	[...]
                    register-contact-trace	[...]
                    register-rate	[...]
                    register-rate-track	[...]
                    rfc2543-branch	[...]
                    rtp	[...]
                    ssl-algorithm	[...]
                    ssl-auth-client	[...]
                    ssl-auth-server	[...]
                    ssl-client-certificate	[...]
                    ssl-client-renegotiation	[...]
                    ssl-max-version	[...]
                    ssl-min-version	[...]
                    ssl-mode	[...]
                    ssl-pfs	[...]
                    ssl-send-empty-frags	[...]
                    ssl-server-certificate	[...]
                    status	[...]
                    strict-register	[...]
                    subscribe-rate	[...]
                    subscribe-rate-track	[...]
                    unknown-header	[...]
                    update-rate	[...]
                    update-rate-track	[...]
                }
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/voip/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/voip/profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/voip/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/voip/profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_voip_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_voip_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_vpn_certificate_ca(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_vpn_certificate_ca\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/vpn/certificate/ca*
            */pm/config/global/obj/vpn/certificate/ca/{ca}*
            */pm/config/adom/{adom}/obj/vpn/certificate/ca*
            */pm/config/adom/{adom}/obj/vpn/certificate/ca/{ca}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *_private_key, auto-update-days, auto-update-days-warning, ca, ca-identifier, est-url, fabric-ca, last-updated, name, non-fabric-name, obsolete, range, scep-url, source, source-ip, ssl-inspection-trusted*

        Examples:
        ---------\n
        >>> init_variable.confdb_vpn_certificate_ca(adom="ADOM Name", name="CA Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                _private_key	[...]
                auto-update-days	[...]
                auto-update-days-warning	[...]
                ca	[...]
                ca-identifier	[...]
                est-url	[...]
                fabric-ca	[...]
                last-updated	[...]
                name	[...]
                non-fabric-name	[...]
                obsolete	[...]
                range	[...]
                scep-url	[...]
                source	[...]
                source-ip	[...]
                ssl-inspection-trusted	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/certificate/ca/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/certificate/ca", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/certificate/ca/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/certificate/ca", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_vpn_certificate_ca.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_vpn_certificate_ca.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_vpn_certificate_ocspserver(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_vpn_certificate_ocspserver\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/vpn/certificate/ocsp-server*
            */pm/config/global/obj/vpn/certificate/ocsp-server/{server}*
            */pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server*
            */pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *cert, name, secondary-cert, secondary-url, source-ip, unavail-action, url*

        Examples:
        ---------\n
        >>> init_variable.confdb_vpn_certificate_ocspserver(adom="ADOM Name", name="Server Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                cert	[...]
                name	[...]
                secondary-cert	[...]
                secondary-url	[...]
                source-ip	[...]
                unavail-action	[...]
                url	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/certificate/ocsp-server/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/certificate/ocsp-server", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_vpn_certificate_ocspserver.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_vpn_certificate_ocspserver.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_vpn_certificate_remote(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_vpn_certificate_remote\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/vpn/certificate/remote*
            */pm/config/global/obj/vpn/certificate/remote/{certificate}*
            */pm/config/adom/{adom}/obj/vpn/certificate/remote*
            */pm/config/adom/{adom}/obj/vpn/certificate/remote/{certificate}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *name, range, remote, source*

        Examples:
        ---------\n
        >>> init_variable.confdb_vpn_certificate_remote(adom="ADOM Name", name="Certificate Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                name	[...]
                range	[...]
                remote	[...]
                source	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/certificate/remote/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/certificate/remote", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/certificate/remote/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/certificate/remote", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_vpn_certificate_remote.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_vpn_certificate_remote.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_vpn_ipsec_fec(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_vpn_ipsec_fec\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/vpn/ipsec/fec*
            */pm/config/global/obj/vpn/ipsec/fec/{profile}*
            */pm/config/adom/{adom}/obj/vpn/ipsec/fec*
            */pm/config/adom/{adom}/obj/vpn/ipsec/fec/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *name*

        Examples:
        ---------\n
        >>> init_variable.confdb_vpn_ipsec_fec(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                mappings	[{
                    bandwidth-bi-threshold	[...]
                    bandwidth-down-threshold	[...]
                    bandwidth-up-threshold	[...]
                    base	[...]
                    latency-threshold	[...]
                    packet-loss-threshold	[...]
                    redundant	[...]
                    seqno	[...]
                }]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/ipsec/fec", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/ipsec/fec/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/ipsec/fec", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_vpn_ipsec_fec.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_vpn_ipsec_fec.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_vpn_ssl_web_hostchecksoftware(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_vpn_ssl_web_hostchecksoftware\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/vpn/ssl/web/host-check-software*
            */pm/config/global/obj/vpn/ssl/web/host-check-software/{name}*
            */pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software*
            */pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{name}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *guid, name, os-type, type, version*

        Examples:
        ---------\n
        >>> init_variable.confdb_vpn_ssl_web_hostchecksoftware(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                check-item-list	[{
                    action	[...]
                    id	[...]
                    md5s	[...]
                    target	[...]
                    type	[...]
                    version	[...]
                }]
                guid	[...]
                name	[...]
                os-type	[...]
                type	[...]
                version	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/ssl/web/host-check-software/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/ssl/web/host-check-software", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_vpn_ssl_web_hostchecksoftware.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_vpn_ssl_web_hostchecksoftware.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_vpn_ssl_web_portal(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_vpn_ssl_web_portal\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/vpn/ssl/web/portal*
            */pm/config/global/obj/vpn/ssl/web/portal/{portal}*
            */pm/config/adom/{adom}/obj/vpn/ssl/web/portal*
            */pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *allow-user-access, auto-connect, client-src-range, clipboard, custom-lang, customize-forticlient-download-url, default-protocol, default-window-height, default-window-width, dhcp-ip-overlap, dhcp-ra-giaddr, dhcp6-ra-linkaddr, display-bookmark, display-connection-tools, display-history, display-status, dns-server1, dns-server2, dns-suffix, exclusive-routing, focus-bookmark, forticlient-download, forticlient-download-method, heading, hide-sso-credential, host-check, host-check-interval, host-check-policy, ip-mode, ip-pools, ipv6-dns-server1, ipv6-dns-server2, ipv6-exclusive-routing, ipv6-pools, ipv6-service-restriction, ipv6-split-tunneling, ipv6-split-tunneling-routing-address, ipv6-split-tunneling-routing-negate, ipv6-tunnel-mode, ipv6-wins-server1, ipv6-wins-server2, keep-alive, landing-page-mode, limit-user-logins, mac-addr-action, mac-addr-check, macos-forticlient-download-url, name, os-check, prefer-ipv6-dns, redir-url, rewrite-ip-uri-ui, save-password, service-restriction, skip-check-for-browser, skip-check-for-unsupported-os, smb-max-version, smb-min-version, smb-ntlmv1-auth, split-tunneling, split-tunneling-routing-address, split-tunneling-routing-negate, theme, tunnel-mode, use-sdwan, user-bookmark, user-group-bookmark, web-mode, windows-forticlient-download-url, wins-server1, wins-server2*

        Examples:
        ---------\n
        >>> init_variable.confdb_vpn_ssl_web_portal(adom="ADOM Name", name="Portal Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                allow-user-access	[...]
                auto-connect	[...]
                bookmark-group	[{
                    bookmarks	[{
                        additional-params	[...]
                        apptype	[...]
                        color-depth	[...]
                        description	[...]
                        domain	[...]
                        folder	[...]
                        form-data	[...]
                        height	[...]
                        host	[...]
                        keyboard-layout	[...]
                        load-balancing-info	[...]
                        logon-password	[...]
                        logon-user	[...]
                        name	[...]
                        port	[...]
                        preconnection-blob	[...]
                        preconnection-id	[...]
                        restricted-admin	[...]
                        security	[...]
                        send-preconnection-id	[...]
                        sso	[...]
                        sso-credential	[...]
                        sso-credential-sent-once	[...]
                        sso-password	[...]
                        sso-username	[...]
                        url	[...]
                        vnc-keyboard-layout	[...]
                        width	[...]
                    }]
                    name	[...]
                }]
                client-src-range	[...]
                clipboard	[...]
                custom-lang	[...]
                customize-forticlient-download-url	[...]
                default-protocol	[...]
                default-window-height	[...]
                default-window-width	[...]
                dhcp-ip-overlap	[...]
                dhcp-ra-giaddr	[...]
                dhcp6-ra-linkaddr	[...]
                display-bookmark	[...]
                display-connection-tools	[...]
                display-history	[...]
                display-status	[...]
                dns-server1	[...]
                dns-server2	[...]
                dns-suffix	[...]
                exclusive-routing	[...]
                focus-bookmark	[...]
                forticlient-download	[...]
                forticlient-download-method	[...]
                heading	[...]
                hide-sso-credential	[...]
                host-check	[...]
                host-check-interval	[...]
                host-check-policy	[...]
                ip-mode	[...]
                ip-pools	[...]
                ipv6-dns-server1	[...]
                ipv6-dns-server2	[...]
                ipv6-exclusive-routing	[...]
                ipv6-pools	[...]
                ipv6-service-restriction	[...]
                ipv6-split-tunneling	[...]
                ipv6-split-tunneling-routing-address	[...]
                ipv6-split-tunneling-routing-negate	[...]
                ipv6-tunnel-mode	[...]
                ipv6-wins-server1	[...]
                ipv6-wins-server2	[...]
                keep-alive	[...]
                landing-page	{
                    form-data	[{
                        name	[...]
                        value	[...]
                    }]
                    sso	[...]
                    sso-credential	[...]
                    sso-password	[...]
                    sso-username	[...]
                    url	[...]
                }
                landing-page-mode	[...]
                limit-user-logins	[...]
                mac-addr-action	[...]
                mac-addr-check	[...]
                mac-addr-check-rule	[{
                    mac-addr-list	[...]
                    mac-addr-mask	[...]
                    name	[...]
                }]
                macos-forticlient-download-url	[...]
                name	[...]
                os-check	[...]
                os-check-list	{
                    action	[...]
                    latest-patch-level	[...]
                    minor-version	[...]
                    name	[...]
                    tolerance	[...]
                }
                prefer-ipv6-dns	[...]
                redir-url	[...]
                rewrite-ip-uri-ui	[...]
                save-password	[...]
                service-restriction	[...]
                skip-check-for-browser	[...]
                skip-check-for-unsupported-os	[...]
                smb-max-version	[...]
                smb-min-version	[...]
                smb-ntlmv1-auth	[...]
                split-dns	[{
                    dns-server1	[...]
                    dns-server2	[...]
                    domains	[...]
                    id	[...]
                    ipv6-dns-server1	[...]
                    ipv6-dns-server2	[...]
                }]
                split-tunneling	[...]
                split-tunneling-routing-address	[...]
                split-tunneling-routing-negate	[...]
                theme	[...]
                tunnel-mode	[...]
                use-sdwan	[...]
                user-bookmark	[...]
                user-group-bookmark	[...]
                web-mode	[...]
                windows-forticlient-download-url	[...]
                wins-server1	[...]
                wins-server2	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/ssl/web/portal", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/ssl/web/portal/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/ssl/web/portal", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_vpn_ssl_web_portal.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_vpn_ssl_web_portal.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_vpn_ssl_web_realm(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_vpn_ssl_web_realm\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/vpn/ssl/web/realm*
            */pm/config/global/obj/vpn/ssl/web/realm/{realm}*
            */pm/config/adom/{adom}/obj/vpn/ssl/web/realm*
            */pm/config/adom/{adom}/obj/vpn/ssl/web/realm/{realm}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *login-page, max-concurrent-user, nas-ip, radius-port, radius-server, url-path, virtual-host, virtual-host-only, virtual-host-server-cert*

        Examples:
        ---------\n
        >>> init_variable.confdb_vpn_ssl_web_realm(adom="ADOM Name", name="Realm Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                login-page	[...]
                max-concurrent-user	[...]
                nas-ip	[...]
                radius-port	[...]
                radius-server	[...]
                url-path	[...]
                virtual-host	[...]
                virtual-host-only	[...]
                virtual-host-server-cert	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/ssl/web/realm/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpn/ssl/web/realm", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/ssl/web/realm/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpn/ssl/web/realm", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_vpn_ssl_web_realm.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_vpn_ssl_web_realm.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_vpnmgr_node(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_vpnmgr_node\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/vpnmgr/node*
            */pm/config/global/obj/vpnmgr/node/{node}*
            */pm/config/adom/{adom}/obj/vpnmgr/node*
            */pm/config/adom/{adom}/obj/vpnmgr/node/{node}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *add-route, assign-ip, assign-ip-from, authpasswd, authusr, authusrgrp, auto-configuration, auto-discovery-receiver, auto-discovery-sender, automatic_routing, banner, default-gateway, dhcp-ra-giaddr, dhcp-server, dns-mode, dns-service, domain, encapsulation, exchange-interface-ip, extgw, extgw_hubip, extgw_p2_per_net, extgwip, hub-public-ip, hub_iface, id, iface, ipsec-lease-hold, ipv4-dns-server1, ipv4-dns-server2, ipv4-dns-server3, ipv4-end-ip, ipv4-name, ipv4-netmask, ipv4-split-exclude, ipv4-split-include, ipv4-start-ip, ipv4-wins-server1, ipv4-wins-server2, l2tp, local-gw, localid, mode-cfg, mode-cfg-ip-version, net-device, network-id, network-overlay, peer, peergrp, peerid, peertype, protocol, public-ip, role, route-overlap, spoke-zone, tunnel-search, unity-support, usrgrp, vpn-interface-priority, vpn-zone, vpntable, xauthtype*

        Examples:
        ---------\n
        >>> init_variable.confdb_vpnmgr_node(adom="ADOM Name", name="Node ID", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                add-route	[...]
                assign-ip	[...]
                assign-ip-from	[...]
                authpasswd	[...]
                authusr	[...]
                authusrgrp	[...]
                auto-configuration	[...]
                auto-discovery-receiver	[...]
                auto-discovery-sender	[...]
                automatic_routing	[...]
                banner	[...]
                default-gateway	[...]
                dhcp-ra-giaddr	[...]
                dhcp-server	[...]
                dns-mode	[...]
                dns-service	[...]
                domain	[...]
                encapsulation	[...]
                exchange-interface-ip	[...]
                extgw	[...]
                extgw_hubip	[...]
                extgw_p2_per_net	[...]
                extgwip	[...]
                hub-public-ip	[...]
                hub_iface	[...]
                id	[...]
                iface	[...]
                ip-range	[{
                    end-ip	[...]
                    id	[...]
                    start-ip	[...]
                }]
                ipsec-lease-hold	[...]
                ipv4-dns-server1	[...]
                ipv4-dns-server2	[...]
                ipv4-dns-server3	[...]
                ipv4-end-ip	[...]
                ipv4-exclude-range	[{
                    end-ip	[...]
                    id	[...]
                    start-ip	[...]
                }]
                ipv4-name	[...]
                ipv4-netmask	[...]
                ipv4-split-exclude	[...]
                ipv4-split-include	[...]
                ipv4-start-ip	[...]
                ipv4-wins-server1	[...]
                ipv4-wins-server2	[...]
                l2tp	[...]
                local-gw	[...]
                localid	[...]
                mode-cfg	[...]
                mode-cfg-ip-version	[...]
                net-device	[...]
                network-id	[...]
                network-overlay	[...]
                peer	[...]
                peergrp	[...]
                peerid	[...]
                peertype	[...]
                protected_subnet	[{
                    addr	[...]
                    seq	[...]
                }]
                protocol	[...]
                public-ip	[...]
                role	[...]
                route-overlap	[...]
                spoke-zone	[...]
                summary_addr	[{
                    addr	[...]
                    priority	[...]
                    seq	[...]
                }]
                tunnel-search	[...]
                unity-support	[...]
                usrgrp	[...]
                vpn-interface-priority	[...]
                vpn-zone	[...]
                vpntable	[...]
                xauthtype	[...]
                scope member	[{
                    name	[...]
                    vdom	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpnmgr/node/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpnmgr/node", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpnmgr/node/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpnmgr/node", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_vpnmgr_node.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_vpnmgr_node.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_vpnmgr_vpntable(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_vpnmgr_vpntable\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/vpnmgr/vpntable*
            */pm/config/global/obj/vpnmgr/vpntable/{vpntable}*
            */pm/config/adom/{adom}/obj/vpnmgr/vpntable*
            */pm/config/adom/{adom}/obj/vpnmgr/vpntable/{vpntable}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *authmethod, auto-zone-policy, certificate, description, dpd, dpd-retrycount, dpd-retryinterval, fcc-enforcement, hub2spoke-zone, ike-version, ike1dhgroup, ike1dpd, ike1keylifesec, ike1mode, ike1natkeepalive, ike1nattraversal, ike1proposal, ike2autonego, ike2dhgroup, ike2keepalive, ike2keylifekbs, ike2keylifesec, ike2keylifetype, ike2proposal, inter-vdom, intf-mode, localid-type, name, negotiate-timeout, network-id, network-overlay, npu-offload, pfs, psk-auto-generate, psksecret, replay, rsa-certificate, spoke2hub-zone, topology, vpn-zone*

        Examples:
        ---------\n
        >>> init_variable.confdb_vpnmgr_vpntable(adom="ADOM Name", name="VPN Table Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                authmethod	[...]
                auto-zone-policy	[...]
                certificate	[...]
                description	[...]
                dpd	[...]
                dpd-retrycount	[...]
                dpd-retryinterval	[...]
                fcc-enforcement	[...]
                hub2spoke-zone	[...]
                ike-version	[...]
                ike1dhgroup	[...]
                ike1dpd	[...]
                ike1keylifesec	[...]
                ike1mode	[...]
                ike1natkeepalive	[...]
                ike1nattraversal	[...]
                ike1proposal	[...]
                ike2autonego	[...]
                ike2dhgroup	[...]
                ike2keepalive	[...]
                ike2keylifekbs	[...]
                ike2keylifesec	[...]
                ike2keylifetype	[...]
                ike2proposal	[...]
                inter-vdom	[...]
                intf-mode	[...]
                localid-type	[...]
                name	[...]
                negotiate-timeout	[...]
                network-id	[...]
                network-overlay	[...]
                npu-offload	[...]
                pfs	[...]
                psk-auto-generate	[...]
                psksecret	[...]
                replay	[...]
                rsa-certificate	[...]
                spoke2hub-zone	[...]
                topology	[...]
                vpn-zone	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpnmgr/vpntable/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/vpnmgr/vpntable", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpnmgr/vpntable/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/vpnmgr/vpntable", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_vpnmgr_vpntable.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_vpnmgr_vpntable.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_waf_mainclass(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_waf_mainclass\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/waf/main-class*
            */pm/config/global/obj/waf/main-class/{class}*
            */pm/config/adom/{adom}/obj/waf/main-class*
            */pm/config/adom/{adom}/obj/waf/main-class/{class}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *id, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_waf_mainclass(adom="ADOM Name", name="Class Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                id	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/waf/main-class/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/waf/main-class", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/waf/main-class/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/waf/main-class", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_waf_mainclass.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_waf_mainclass.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_waf_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_waf_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/waf/profile*
            */pm/config/global/obj/waf/profile/{profile}*
            */pm/config/adom/{adom}/obj/waf/profile*
            */pm/config/adom/{adom}/obj/waf/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, extended-log, external, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_waf_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                address-list	{
                    blocked-address	[...]
                    blocked-log	[...]
                    severity	[...]
                    status	[...]
                    trusted-address	[...]
                }
                comment	[...]
                constraint	{
                    content-length	{
                        action	[...]
                        length	[...]
                        log	[...]
                        severity	[...]
                        status	[...]
                    }
                    exception	[{
                        address	[...]
                        content-length	[...]
                        header-length	[...]
                        hostname	[...]
                        id	[...]
                        line-length	[...]
                        malformed	[...]
                        max-cookie	[...]
                        max-header-line	[...]
                        max-range-segment	[...]
                        max-url-param	[...]
                        method	[...]
                        param-length	[...]
                        pattern	[...]
                        regex	[...]
                        url-param-length	[...]
                        version	[...]
                    }]
                    header-length	{
                        action	[...]
                        length	[...]
                        log	[...]
                        severity	[...]
                        status	[...]
                    }
                    hostname	{
                        action	[...]
                        log	[...]
                        severity	[...]
                        status	[...]
                    }
                    line-length	{
                        action	[...]
                        length	[...]
                        log	[...]
                        severity	[...]
                        status	[...]
                    }
                    malformed	{
                        action	[...]
                        log	[...]
                        severity	[...]
                        status	[...]
                    }
                    max-cookie	{
                        action	[...]
                        log	[...]
                        max-cookie	[...]
                        severity	[...]
                        status	[...]
                    }
                    max-header-line	{
                        action	[...]
                        log	[...]
                        max-header-line	[...]
                        severity	[...]
                        status	[...]
                    }
                    max-range-segment	{
                        action	[...]
                        log	[...]
                        max-range-segment	[...]
                        severity	[...]
                        status	[...]
                    }
                    max-url-param	{
                        action	[...]
                        log	[...]
                        max-url-param	[...]
                        severity	[...]
                        status	[...]
                    }
                    method	{
                        action	[...]
                        log	[...]
                        severity	[...]
                        status	[...]
                    }
                    param-length	{
                        action	[...]
                        length	[...]
                        log	[...]
                        severity	[...]
                        status	[...]
                    }
                    url-param-length	{
                        action	[...]
                        length	[...]
                        log	[...]
                        severity	[...]
                        status	[...]
                    }
                    version	{
                        action	[...]
                        log	[...]
                        severity	[...]
                        status	[...]
                    }
                }
                extended-log	[...]
                external	[...]
                method	{
                    default-allowed-methods	[...]
                    log	[...]
                    method-policy	[{
                        address	[...]
                        allowed-methods	[...]
                        id	[...]
                        pattern	[...]
                        regex	[...]
                    }]
                    severity	[...]
                    status	[...]
                }
                name	[...]
                signature	{
                    credit-card-detection-threshold	[...]
                    custom-signature	[{
                        action	[...]
                        case-sensitivity	[...]
                        direction	[...]
                        log	[...]
                        name	[...]
                        pattern	[...]
                        severity	[...]
                        status	[...]
                        target	[...]
                    }]
                    disabled-signature	[...]
                    disabled-sub-class	[...]
                    main-class	{
                        action	[...]
                        id	[...]
                        log	[...]
                        severity	[...]
                        status	[...]
                    }
                }
                url-access	[{
                    access-pattern	[{
                        id	[...]
                        negate	[...]
                        pattern	[...]
                        regex	[...]
                        srcaddr	[...]
                    }]
                    action	[...]
                    address	[...]
                    id	[...]
                    log	[...]
                    severity	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/waf/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/waf/profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/waf/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/waf/profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_waf_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_waf_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_waf_signature(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_waf_signature\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/waf/signature*
            */pm/config/global/obj/waf/signature/{signature}*
            */pm/config/adom/{adom}/obj/waf/signature*
            */pm/config/adom/{adom}/obj/waf/signature/{signature}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *desc, id*

        Examples:
        ---------\n
        >>> init_variable.confdb_waf_signature(adom="ADOM Name", name="Signature ID", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                desc	[...]
                id	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/waf/signature/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/waf/signature", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/waf/signature/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/waf/signature", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_waf_signature.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_waf_signature.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_waf_subclass(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_waf_subclass\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/waf/sub-class*
            */pm/config/global/obj/waf/sub-class/{class}*
            */pm/config/adom/{adom}/obj/waf/sub-class*
            */pm/config/adom/{adom}/obj/waf/sub-class/{class}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *id, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_waf_subclass(adom="ADOM Name", name="Class Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                id	[...]
                name	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/waf/sub-class/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/waf/sub-class", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/waf/sub-class/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/waf/sub-class", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_waf_subclass.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_waf_subclass.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_wanopt_authgroup(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_wanopt_authgroup\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/wanopt/auth-group*
            */pm/config/global/obj/wanopt/auth-group/{group}*
            */pm/config/adom/{adom}/obj/wanopt/auth-group*
            */pm/config/adom/{adom}/obj/wanopt/auth-group/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *auth-method, cert, name, peer, peer-accept, psk*

        Examples:
        ---------\n
        >>> init_variable.confdb_wanopt_authgroup(adom="ADOM Name", name="Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                auth-method	[...]
                cert	[...]
                name	[...]
                peer	[...]
                peer-accept	[...]
                psk	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/wanopt/auth-group/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/wanopt/auth-group", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/wanopt/auth-group/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/wanopt/auth-group", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_wanopt_authgroup.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_wanopt_authgroup.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_wanopt_peer(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_wanopt_peer\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/wanopt/peer*
            */pm/config/global/obj/wanopt/peer/{peer}*
            */pm/config/adom/{adom}/obj/wanopt/peer*
            */pm/config/adom/{adom}/obj/wanopt/peer/{peer}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *ip, peer-host-id*

        Examples:
        ---------\n
        >>> init_variable.confdb_wanopt_peer(adom="ADOM Name", name="Peer ID", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                ip	[...]
                peer-host-id	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/wanopt/peer/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/wanopt/peer", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/wanopt/peer/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/wanopt/peer", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_wanopt_peer.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_wanopt_peer.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_wanopt_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_wanopt_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/wanopt/profile*
            */pm/config/global/obj/wanopt/profile/{profile}*
            */pm/config/adom/{adom}/obj/wanopt/profile*
            */pm/config/adom/{adom}/obj/wanopt/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *auth-group, comments, name, transparent*

        Examples:
        ---------\n
        >>> init_variable.confdb_wanopt_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                auth-group	[...]
                cifs	{
                    byte-caching	[...]
                    prefer-chunking	[...]
                    protocol-opt	[...]
                    secure-tunnel	[...]
                    status	[...]
                    tunnel-sharing	[...]
                }
                comments	[...]
                ftp	{
                    byte-caching	[...]
                    prefer-chunking	[...]
                    protocol-opt	[...]
                    secure-tunnel	[...]
                    status	[...]
                    tunnel-sharing	[...]
                }
                http	{
                    byte-caching	[...]
                    prefer-chunking	[...]
                    protocol-opt	[...]
                    secure-tunnel	[...]
                    ssl	[...]
                    status	[...]
                    tunnel-sharing	[...]
                }
                mapi	{
                    byte-caching	[...]
                    secure-tunnel	[...]
                    status	[...]
                    tunnel-sharing	[...]
                }
                name	[...]
                tcp	{
                    byte-caching	[...]
                    byte-caching-opt	[...]
                    port	[...]
                    secure-tunnel	[...]
                    ssl	[...]
                    ssl-port	[...]
                    status	[...]
                    tunnel-sharing	[...]
                }
                transparent	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/wanopt/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/wanopt/profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/wanopt/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/wanopt/profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_wanopt_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_wanopt_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_webproxy_forwardserver(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_webproxy_forwardserver\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/web-proxy/forward-server*
            */pm/config/global/obj/web-proxy/forward-server/{server}*
            */pm/config/adom/{adom}/obj/web-proxy/forward-server*
            */pm/config/adom/{adom}/obj/web-proxy/forward-server/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *addr-type, comment, fqdn, healthcheck, ip, ipv6, masquerade, monitor, name, password, port, server-down-option, username*

        Examples:
        ---------\n
        >>> init_variable.confdb_webproxy_forwardserver(adom="ADOM Name", name="Server Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                addr-type	[...]
                comment	[...]
                fqdn	[...]
                healthcheck	[...]
                ip	[...]
                ipv6	[...]
                masquerade	[...]
                monitor	[...]
                name	[...]
                password	[...]
                port	[...]
                server-down-option	[...]
                username	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/web-proxy/forward-server/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/web-proxy/forward-server", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/web-proxy/forward-server/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/web-proxy/forward-server", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_webproxy_forwardserver.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_webproxy_forwardserver.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_webproxy_forwardserver_grp(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_webproxy_forwardserver_grp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/web-proxy/forward-server-group*
            */pm/config/global/obj/web-proxy/forward-server-group/{group}*
            */pm/config/adom/{adom}/obj/web-proxy/forward-server-group*
            */pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{group}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *affinity, group-down-option, ldb-method, name*

        Examples:
        ---------\n
        >>> init_variable.confdb_webproxy_forwardserver_grp(adom="ADOM Name", name="Group Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                affinity	[...]
                group-down-option	[...]
                ldb-method	[...]
                name	[...]
                server-list	[{
                    name	[...]
                    weight	[...]
                }]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/web-proxy/forward-server-group", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/web-proxy/forward-server-group/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/web-proxy/forward-server-group", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_webproxy_forwardserver_grp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_webproxy_forwardserver_grp.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_webproxy_profile(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_webproxy_profile\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/web-proxy/profile*
            */pm/config/global/obj/web-proxy/profile/{profile}*
            */pm/config/adom/{adom}/obj/web-proxy/profile*
            */pm/config/adom/{adom}/obj/web-proxy/profile/{profile}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *header-client-ip, header-front-end-https, header-via-request, header-via-response, header-x-authenticated-groups, header-x-authenticated-user, header-x-forwarded-client-cert, header-x-forwarded-for, log-header-change, name, strip-encoding*

        Examples:
        ---------\n
        >>> init_variable.confdb_webproxy_profile(adom="ADOM Name", name="Profile Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                header-client-ip	[...]
                header-front-end-https	[...]
                header-via-request	[...]
                header-via-response	[...]
                header-x-authenticated-groups	[...]
                header-x-authenticated-user	[...]
                header-x-forwarded-client-cert	[...]
                header-x-forwarded-for	[...]
                headers	[{
                    action	[...]
                    add-option	[...]
                    base64-encoding	[...]
                    content	[...]
                    dstaddr	[...]
                    dstaddr6	[...]
                    id	[...]
                    name	[...]
                    protocol	[...]
                }]
                log-header-change	[...]
                name	[...]
                strip-encoding	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/web-proxy/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/web-proxy/profile", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/web-proxy/profile/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/web-proxy/profile", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_webproxy_profile.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_webproxy_profile.__name__, msg=f"Login state is {self.loginstate}")
        return response
    
    def confdb_webproxy_wisp(self, adom:str=None, name:str=None, method:str="get", option:str=None, data:dict=None):
        """
        bcfortiapi.fmg.fmgapi.confdb_webproxy_wisp\n

        API Endpoints:
        --------------\n
            */pm/config/global/obj/web-proxy/wisp*
            */pm/config/global/obj/web-proxy/wisp/{server}*
            */pm/config/adom/{adom}/obj/web-proxy/wisp*
            */pm/config/adom/{adom}/obj/web-proxy/wisp/{server}*
        
        Mandatory Parameters:
        ---------------------\n
            *None*
        
        HTTP Methods:
        -------------\n
            *get, add, set, update, delete, clone*
        
        Options:
        --------\n
            *count, scope member, datasrc, get reserved, syntax*

        Fields:
        -------\n
            *comment, max-connections, name, outgoing-ip, server-ip, server-port, timeout*

        Examples:
        ---------\n
        >>> init_variable.confdb_webproxy_wisp(adom="ADOM Name", name="Server Name", method="HTTP Method", fields=[List Object], option="Option", data={Dictionary Object})

        Data Structure:
        ---------------\n
        >>> data = {
                comment	[...]
                max-connections	[...]
                name	[...]
                outgoing-ip	[...]
                server-ip	[...]
                server-port	[...]
                timeout	[...]
            }

        """
        if self.loginstate == True:
            if adom is not None:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/web-proxy/wisp/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/adom/{adom}/obj/web-proxy/wisp", session=self.session_id, verbose=1, data=data, option=option)
            else:
                if name is not None:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/web-proxy/wisp/{name}", session=self.session_id, verbose=1, data=data, option=option)
                else:
                    self._payload_builder(method=method, endpoint=f"/pm/config/global/obj/web-proxy/wisp", session=self.session_id, verbose=1, data=data, option=option)
            response = self._request()
            if self.debug == True:
                self._debugger(fnct=self.confdb_webproxy_wisp.__name__, resp=response, mode=["std", "resp"])
        else:
            response = self._json_error(fnct=self.confdb_webproxy_wisp.__name__, msg=f"Login state is {self.loginstate}")
        return response