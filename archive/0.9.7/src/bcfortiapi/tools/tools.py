#bcfortiapi.tools
#Additional tools for use with bcfortiapi
#Created by Benjamin Court 22-02-2026
#Last Updated: 22-03-2026

"""
bcfortiapi.tools\n
    *Additional tools for use with bcfortiapi*

Dependencies:
------------\n
    *None*

Examples:
---------\n
    *Import into Python script*
>>> import bcfortiapi

    *Initialise instance of tools within script*
>>> init_variable = bcfortiapi.toolbox()

Notes:
------\n
    *None*

"""

import socket

class toolbox:

    #----------------------------------------
    #---------- Internal Functions ----------
    #----------------------------------------

    def __init__(self, debug:bool=False):
        self.debug = debug

    def _fr_list_itr(self, src, key, value, oldvalue:str=None, match_path:list=[], current_path:list=[]):
        for i in range(len(src)):
            current_path.append(i)
            if type(src[i]) == dict:
                src[i] = self._fr_dict_itr(src=src[i], key=key, value=value, oldvalue=oldvalue, match_path=match_path, current_path=current_path)
            elif type(src[i]) == list:
                src[i] = self._fr_list_itr(src=src[i], key=key, value=value, oldvalue=oldvalue, match_path=match_path, current_path=current_path)
            else:
                continue
            current_path.pop()
        return src
    
    def _fr_dict_itr(self, src, key, value, oldvalue:str=None, match_path:list=[], current_path:list=[]):
        for k, v in dict(src).items():
            if type(v) == list:
                current_path.append(k)
                if self.debug == True:
                    self._debugger(fnct=self._fr_dict_itr.__name__, data={
                        'Key': k,
                        'Key Value': v,
                        'Old Value': oldvalue,
                        'New Value': value,
                        'Current Path': current_path,
                        'Matched Path': match_path
                        })
                if k == key:
                    if match_path is not None:
                        if str(match_path) == str(current_path):
                            if oldvalue is not None:
                                if v == oldvalue:
                                    src[k] = value
                                    if self.debug == True:
                                        self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                            'Match Parameters: ': 'Path, Key, Old Value',
                                            'Key': k,
                                            'Key Value': v,
                                            'Old Value': oldvalue,
                                            'New Value': value,
                                            'Current Path': current_path,
                                            'Matched Path': match_path
                                            })
                            else:
                                src[k] = value
                                if self.debug == True:
                                    self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                        'Match Parameters: ': 'Path, Key',
                                        'Key': k,
                                        'Key Value': v,
                                        'Old Value': oldvalue,
                                        'New Value': value,
                                        'Current Path': current_path,
                                        'Matched Path': match_path
                                        })
                        else:
                            src[k] = v
                            v = self._fr_list_itr(src=v, key=key, value=value, oldvalue=oldvalue, match_path=match_path, current_path=current_path)
                    else:
                        if oldvalue is not None:
                            if v == oldvalue:
                                src[k] = value
                                if self.debug == True:
                                    self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                        'Match Parameters: ': 'Key, Old Value',
                                        'Key': k,
                                        'Key Value': v,
                                        'Old Value': oldvalue,
                                        'New Value': value,
                                        'Current Path': current_path,
                                        'Matched Path': match_path
                                        })
                            else:
                                v = self._fr_list_itr(src=v, key=key, value=value, oldvalue=oldvalue, match_path=match_path, current_path=current_path)
                        else:
                            src[k] = value
                            if self.debug == True:
                                self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                    'Match Parameters: ': 'Key',
                                    'Key': k,
                                    'Key Value': v,
                                    'Old Value': oldvalue,
                                    'New Value': value,
                                    'Current Path': current_path,
                                    'Matched Path': match_path
                                    })
                            v = self._fr_list_itr(src=v, key=key, value=value, oldvalue=oldvalue, match_path=match_path, current_path=current_path)
                else:
                    v = self._fr_list_itr(src=v, key=key, value=value, oldvalue=oldvalue, match_path=match_path, current_path=current_path)
            elif type(v) == dict:
                current_path.append(k)
                if self.debug == True:
                    self._debugger(fnct=self._fr_dict_itr.__name__, data={
                        'Key': k,
                        'Key Value': v,
                        'Old Value': oldvalue,
                        'New Value': value,
                        'Current Path': current_path,
                        'Matched Path': match_path
                        })
                if k == key:
                    if match_path is not None:
                        if str(match_path) == str(current_path):
                            if oldvalue is not None:
                                if v == oldvalue:
                                    src[k] = value
                                    if self.debug == True:
                                        self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                            'Match Parameters: ': 'Path, Key, Old Value',
                                            'Key': k,
                                            'Key Value': v,
                                            'Old Value': oldvalue,
                                            'New Value': value,
                                            'Current Path': current_path,
                                            'Matched Path': match_path
                                            })
                            else:
                                src[k] = value
                                if self.debug == True:
                                    self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                        'Match Parameters: ': 'Path, Key',
                                        'Key': k,
                                        'Key Value': v,
                                        'Old Value': oldvalue,
                                        'New Value': value,
                                        'Current Path': current_path,
                                        'Matched Path': match_path
                                        })
                        else:
                            src[k] = v
                            v = self._fr_dict_itr(src=v, key=key, value=value, oldvalue=oldvalue, match_path=match_path, current_path=current_path)
                    else:
                        if oldvalue is not None:
                            if v == oldvalue:
                                src[k] = value
                                if self.debug == True:
                                    self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                        'Match Parameters: ': 'Key, Old Value',
                                        'Key': k,
                                        'Key Value': v,
                                        'Old Value': oldvalue,
                                        'New Value': value,
                                        'Current Path': current_path,
                                        'Matched Path': match_path
                                        })
                            else:
                                v = self._fr_dict_itr(src=v, key=key, value=value, oldvalue=oldvalue, match_path=match_path, current_path=current_path)
                        else:
                            src[k] = value
                            if self.debug == True:
                                self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                    'Match Parameters: ': 'Key',
                                    'Key': k,
                                    'Key Value': v,
                                    'Old Value': oldvalue,
                                    'New Value': value,
                                    'Current Path': current_path,
                                    'Matched Path': match_path
                                    })
                            v = self._fr_dict_itr(src=v, key=key, value=value, oldvalue=oldvalue, match_path=match_path, current_path=current_path)
                else:
                    v = self._fr_dict_itr(src=v, key=key, value=value, oldvalue=oldvalue, match_path=match_path, current_path=current_path)
            elif k == key:
                current_path.append(k)
                if self.debug == True:
                    self._debugger(fnct=self._fr_dict_itr.__name__, data={
                        'Key': k,
                        'Key Value': v,
                        'Old Value': oldvalue,
                        'New Value': value,
                        'Current Path': current_path,
                        'Matched Path': match_path
                        })
                if match_path is not None:
                    if str(match_path) == str(current_path):
                        if oldvalue is not None:
                            if v == oldvalue:
                                src[k] = value
                                if self.debug == True:
                                    self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                        'Match Parameters: ': 'Path, Key, Old Value',
                                        'Key': k,
                                        'Key Value': v,
                                        'Old Value': oldvalue,
                                        'New Value': value,
                                        'Current Path': current_path,
                                        'Matched Path': match_path
                                        })
                        else:
                            src[k] = value
                            if self.debug == True:
                                self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                    'Match Parameters: ': 'Path, Key',
                                    'Key': k,
                                    'Key Value': v,
                                    'Old Value': oldvalue,
                                    'New Value': value,
                                    'Current Path': current_path,
                                    'Matched Path': match_path
                                    })
                    else:
                        src[k] = v
                else:
                    if oldvalue is not None:
                        if v == oldvalue:
                            src[k] = value
                            if self.debug == True:
                                self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                    'Match Parameters: ': 'Key, Old Value',
                                    'Key': k,
                                    'Key Value': v,
                                    'Old Value': oldvalue,
                                    'New Value': value,
                                    'Current Path': current_path,
                                    'Matched Path': match_path
                                    })
                    else:
                        src[k] = value
                        if self.debug == True:
                            self._debugger(fnct=self._fr_dict_itr.__name__, data={
                                'Match Parameters: ': 'Key',
                                'Key': k,
                                'Key Value': v,
                                'Old Value': oldvalue,
                                'New Value': value,
                                'Current Path': current_path,
                                'Matched Path': match_path
                                })
            else:
                continue
            current_path.pop()
        return src
    
    def _jc_list_itr(self, list_src):
        list_config_update = []
        list_config_update_sub = []
        if len(str(list_src)) > 0:
            for i in range(len(list_src)):
                if (not list_src[i] == None):
                    if type(list_src[i]) == dict:
                        list_config_update_sub = self._jc_dict_itr(dict_src=list_src[i])
                    elif type(list_src[i]) == list:
                        list_config_update_sub = self._jc_list_itr(list_src=list_src[i])
                    if len(list_config_update_sub) > 0:
                        for j in range(len(list_config_update_sub)):
                            list_config_update.append(list_config_update_sub[j])
        return list_config_update
    
    def _jc_dict_itr(self, dict_src):
        dict_config_update = []
        dict_config_update_sub = []
        conf_mode = False
        if len(str(dict_src)) > 0:
            if ('id' in dict(dict_src)) or ('vdom' in dict(dict_src)):
                if 'name' in dict(dict_src):
                    dict_config_update.append(f'edit "{str(dict_src['name']).strip()}"')
                else:
                    dict_config_update.append(f"edit {str(dict_src['id']).strip()}")
            for k, v in dict(dict_src).items():
                conf_mode = False
                if (not k == "id") and (not k == "name") and (not k == "q_origin_key"):
                    if (not v == None):
                        if len(str(v)) > 0:
                            if type(v) == list:
                                if len(v) > 0:
                                    if type(v[0]) == dict:
                                        if 'id' in dict(v[0]):
                                            conf_mode = True
                                    if conf_mode == True:
                                        dict_config_update.append(f"config {str(k).strip()}")
                                        dict_config_update_sub = self._jc_list_itr(list_src=v)
                                    else:
                                        values = []
                                        value_string = ""
                                        for j in range(len(v)):
                                            if type(v[j]) == dict:
                                                for x, y in dict(v[j]).items():
                                                    if (not x == "q_origin_key"):
                                                        values.append(y)
                                            else:
                                                values.append((v[j]))
                                        if len(values) > 0:
                                            for a in range(len(values)):
                                                if type(values[a]) == int:
                                                    value_string = f"{value_string} {values[a]}"
                                                else:
                                                    value_string = f'{value_string} "{values[a]}"'
                                        if len(value_string) > 0:
                                            dict_config_update_sub = [f'set {k} {str(value_string).strip()}']
                            elif type(v) == dict:
                                conf_mode = True
                                dict_config_update.append(f"config {str(k).strip()}")
                                dict_config_update_sub = self._jc_dict_itr(dict_src=v)
                            else:
                                if (type(v) == str) and (" " in str(v)):
                                    if (k == "allowaccess"):
                                        dict_config_update_sub = [f'set {k} {str(v).replace('"',"").strip()}']
                                    elif (not str(v).startswith("ENC ")):
                                        dict_config_update_sub = [f'set {k} "{str(v).replace('"',"").strip()}"']
                                    else:
                                        dict_config_update_sub = [f'set {k} {str(v).replace('"',"").strip()}']    
                                else:
                                    dict_config_update_sub = [f'set {k} {str(v).replace('"',"").strip()}']
                            if len(dict_config_update_sub) > 0:
                                for i in range(len(dict_config_update_sub)):
                                    dict_config_update.append(dict_config_update_sub[i])
                            dict_config_update_sub = []
                            if conf_mode == True:
                                dict_config_update.append("end")
            if ('id' in dict(dict_src)) or ('vdom' in dict(dict_src)):
                dict_config_update.append("next")
        return dict_config_update

    def _debugger(self, fnct=None, data=None):
        if fnct is not None:
            print(f"*** bcfortiapi.tools.toolbox.{str(fnct)} Debug Output ***")
            print("---------------------------------------------------------------------------------")
        else:
            print(f"*** bcfortiapi.tools.toolbox Debug Output ***")
            print("---------------------------------------------------------------------------------")
        if type(data) == list:
            for i in range(len(data)):
                if type(data[i]) == dict:
                    for k, v in dict(data[i]).items():
                        print(f"{str(k)}: {str(v)}")
                else:
                    print(f"Data: {str(data[i])}")
        elif type(data) == dict:
            for k, v in dict(data).items():
                print(f"{str(k)}: {str(v)}")
        else:
            print(f"Data: {str(data)}")
        print("")

    #---------------------------
    #---------- Tools ----------
    #---------------------------

    def connection_check(self, dst:str=None, port:int=None, timeout:float=3.0, ipv6:bool=False):
        """
        bcfortiapi.tools.toolbox.connection_check\n

        Inputs:
        -------\n
            *Destination (string - IP address or FQDN of target device), Port (integer - TCP port number to test), Timeout (float - timeout value in seconds), IPv6 (enabled - True/False)*

        Outputs:
        --------\n
            *Test result (bool), status message (string)*

        Functions:
        ----------\n
            *Check if a TCP port is open on a network device*

        """
        status = None
        result = False
        if dst is not None:
            if port is not None:
                try:
                    if ipv6 == True:
                        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    else:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((dst, port))
                    result = True
                    status = f"Connection to {str(dst)} successful on port {str(port)}"
                    if self.debug == True:
                        self._debugger(fnct=self.connection_check.__name__, data={
                        'Connected': str(result),
                        'Status': str(status)
                        })
                except ConnectionError as error:
                    result = False
                    status = "General connection error"
                    if self.debug == True:
                        self._debugger(fnct=self.connection_check.__name__, data={
                            'Connected': str(result),
                            'Status': str(status),
                            'Details': str(error)
                            })
                except ConnectionAbortedError as error:
                    result = False
                    status = "Connection aborted"
                    if self.debug == True:
                        self._debugger(fnct=self.connection_check.__name__, data={
                            'Connected': str(result),
                            'Status': str(status),
                            'Details': str(error)
                            })
                except ConnectionResetError as error:
                    result = False
                    status = "Connection reset"
                    if self.debug == True:
                        self._debugger(fnct=self.connection_check.__name__, data={
                            'Connected': str(result),
                            'Status': str(status),
                            'Details': str(error)
                            })
                except ConnectionRefusedError as error:
                    result = False
                    status = "Connection refused"
                    if self.debug == True:
                        self._debugger(fnct=self.connection_check.__name__, data={
                            'Connected': str(result),
                            'Status': str(status),
                            'Details': str(error)
                            })
                except socket.timeout as error:
                    result = False
                    status = f"Connection timed out after {str(timeout)} seconds"
                    if self.debug == True:
                        self._debugger(fnct=self.connection_check.__name__, data={
                            'Connected': str(result),
                            'Status': str(status),
                            'Details': str(error)
                            })
                except Exception as error:
                    result = False
                    status = "General error"
                    if self.debug == True:
                        self._debugger(fnct=self.connection_check.__name__, data={
                            'Connected': str(result),
                            'Status': str(status),
                            'Details': str(error)
                            })
                finally:
                    sock.close()
            else:
                self._debugger(fnct=self.connection_check.__name__, data={'ERR': 'TCP port number not specified'})
        else:
            self._debugger(fnct=self.connection_check.__name__, data={'ERR': 'IP address or FQDN not specified'})
        return result, status

    def find_replace(self, dataset=None, updates=None):
        """
        bcfortiapi.tools.toolbox.find_replace\n

        Inputs:
        -------\n
            *Dataset (dictionary or list - can contain nested list/dictionary objects), Updates (dictionary - eg. {'key1': newvalue1, 'key2': ['oldvalue2', 'newvalue2', [list of list indices (int) and dictionary keys (str) comprising path to target key]]})*
        
        Outputs:
        --------\n
            *Updated dataset object*

        Functions:
        ----------\n
            *Find all instances of specified key within dataset and replace existing value with specified value*

        Example Update Dictionaries:
        ----------------------------\n
            *Replace all instances of KEY with NEW_VALUE*
        >>> {
                'KEY': 'NEW_VALUE'
            }
            {
                'KEY': [None, 'NEW_VALUE', None]
            }
            #NEW_VALUE can be any Python type

            *Replace all instances of KEY with NEW_VALUE where existing value matches OLD_VALUE*
        >>> {
                'KEY': ['OLD_VALUE', 'NEW_VALUE', None]
            }
            #NEW_VALUE and OLD_VALUE can be any Python type

            *Replace all instances of KEY with NEW_VALUE where path to key matches PATH*
        >>> {
                'KEY': [None, 'NEW_VALUE', ['PATH']]
            }
            #NEW_VALUE can be any Python type
            #Path list represents the sequence of nodes (list indices and dictionary keys) to match against (excluding the target key itself) - eg. [0, 'data', 4, 'sub_data'] will match [0]['data'][4]['sub_data']['KEY']

            **Replace all instances of KEY with NEW_VALUE where existing value matches OLD_VALUE and path to key matches PATH*
        >>> {
                'KEY': ['OLD_VALUE', 'NEW_VALUE', ['PATH']]
            }
            #NEW_VALUE and OLD_VALUE can be any Python type
            #Path list represents the sequence of nodes (list indices and dictionary keys) to match against (excluding the target key itself) - eg. [0, 'data', 4, 'sub_data'] will match [0]['data'][4]['sub_data']['KEY']

        """
        if dataset is not None:
            if updates is not None:
                if type(updates) == dict:
                    for search_key, new_value in dict(updates).items():
                        if type(new_value) == list:
                            if len(new_value) == 3:
                                nv_original = new_value[0]
                                nv_new = new_value[1]
                                if new_value[2] is not None:
                                    nv_path = list(new_value[2])
                                    nv_path.append(search_key)
                                else:
                                    nv_path = new_value[2]
                                if self.debug == True:
                                    self._debugger(fnct=self.find_replace.__name__, data={
                                        'Search Key': str(search_key),
                                        'Search Path': str(nv_path),
                                        'Original Value': str(nv_original),
                                        'New Value': str(nv_new)
                                        })
                                try:
                                    if type(dataset) == dict:
                                        dataset = self._fr_dict_itr(src=dataset, key=search_key, value=nv_new, oldvalue=nv_original, match_path=nv_path, current_path=[])
                                    elif type(dataset) == list:
                                        dataset = self._fr_list_itr(src=dataset, key=search_key, value=nv_new, oldvalue=nv_original, match_path=nv_path, current_path=[])
                                    else:
                                        self._debugger(fnct=self.find_replace.__name__, data={'ERR': 'Dataset object is not a valid Python list or dictionary'})
                                except Exception as error:
                                    self._debugger(fnct=self.find_replace.__name__, data={'ERR': str(error)})
                            else:
                                self._debugger(fnct=self.find_replace.__name__, data={
                                    'ERR': f'Updates entry contains a list object of invalid length - {str(len(new_value))}',
                                    'Correct Format': '[Old Value (str or None), New Value (str), Path (list or None)]',
                                    'Example': "['oldvalue', 'newvalue', [0, 'data', 1, 'subdata', 5]]"
                                    })
                        else:
                            if self.debug == True:
                                self._debugger(fnct=self.find_replace.__name__, data={
                                    'Search Key': str(search_key),
                                    'New Value': str(new_value)
                                    })
                            try:
                                if type(dataset) == dict:
                                    dataset = self._fr_dict_itr(src=dataset, key=search_key, value=new_value, oldvalue=None, match_path=None, current_path=[])
                                elif type(dataset) == list:
                                    dataset = self._fr_list_itr(src=dataset, key=search_key, value=new_value, oldvalue=None, match_path=None, current_path=[])
                                else:
                                    self._debugger(fnct=self.find_replace.__name__, data={'ERR': 'Dataset object is not a valid Python list or dictionary'})
                            except Exception as error:
                                self._debugger(fnct=self.find_replace.__name__, data={'ERR': str(error)})
                else:
                    self._debugger(fnct=self.find_replace.__name__, data={'ERR': 'Updates object is not a valid Python dictionary'})
            else:
                self._debugger(fnct=self.find_replace.__name__, data={'ERR': 'Updates object not specified'})
        else:
            self._debugger(fnct=self.find_replace.__name__, data={'ERR': 'Dataset object not specified'})
        if self.debug == True:
            self._debugger(fnct=self.find_replace.__name__, data={'Updated Data': dataset})
        return dataset
    
    def fgt_json_to_cli(self, src):
        """
        bcfortiapi.tools.toolbox.fgt_json_to_cli\n

        Inputs:
        -------\n
            *Source (list or dictionary object returned from fgtapi GET)*

        Outputs:
        --------\n
            *List object containing each CLI command, print or write to file each line in sequence to create a FortiOS CLI script*

        Functions:
        ----------\n
            *Convert JSON response from FortiGate API to equivalent FortiOS CLI script*

        """
        config_lines = []
        if src is not None:
            config_update = []
            if type(src) == list:
                config_update = self._jc_list_itr(src=src)
                for i in config_update:
                    config_lines.append(i)
            elif type(src) == dict:
                header = False
                try:
                    if ('path' in dict(src)) and ('name' in dict(src)):
                        header = True
                        src_sub = src['results']
                except KeyError:
                    header = False
                if header == True:
                    config_lines.append(f"config {str(src['path']).replace(".", " ").strip()} {str(src['name']).strip()}")
                    if type(src_sub) == dict:
                        config_update = self._jc_dict_itr(dict_src=src_sub)
                        for i in config_update:
                            config_lines.append(i)
                    elif type(src_sub) == list:
                        config_update = self._jc_list_itr(list_src=src_sub)
                        for i in config_update:
                            config_lines.append(i)
                else:
                    config_update = self._jc_dict_itr(dict_src=src)
                    for i in config_update:
                        config_lines.append(i)
                if header == True:
                    config_lines.append("end")
            else:
                self._debugger(fnct=self.find_replace.__name__, data={'ERR': 'Source object is not a valid Python list or dictionary'})
        else:
            self._debugger(fnct=self.find_replace.__name__, data={'ERR': 'Source object not specified'})
        if self.debug == True:
            self._debugger(fnct=self.find_replace.__name__, data={'CLI Commands': config_lines})
        return config_lines
