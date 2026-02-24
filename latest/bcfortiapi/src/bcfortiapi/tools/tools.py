#bcfortiapi.tools
#Additional tools for use with bcfortiapi
#Created by Benjamin Court 22-02-2026
#Last Updated: 24-02-2026

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

class toolbox:

    #----------------------------------------
    #---------- Internal Functions ----------
    #----------------------------------------

    def __init__(self, debug:bool=False):
        self.debug = debug

    def _list_itr(self, src, key, value, match_path:list=[], current_path:list=[]):
        for i in range(len(src)):
            current_path.append(i)
            if type(src[i]) == dict:
                src[i] = self._dict_itr(src=src[i], key=key, value=value, match_path=match_path, current_path=current_path)
            elif type(src[i]) == list:
                src[i] = self._list_itr(src=src[i], key=key, value=value, match_path=match_path, current_path=current_path)
            else:
                continue
            current_path.pop()
        return src
    
    def _dict_itr(self, src, key, value, match_path:list=[], current_path:list=[]):
        for k, v in dict(src).items():
            if type(v) == list:
                current_path.append(k)
                v = self._list_itr(src=v, key=key, value=value, match_path=match_path, current_path=current_path)
            elif type(v) == dict:
                current_path.append(k)
                v = self._dict_itr(src=v, key=key, value=value, match_path=match_path, current_path=current_path)
            elif k == key:
                current_path.append(k)
                if match_path is not None:
                    if str(match_path) == str(current_path):
                        src[k] = value
                        print(f"Match Found with path: {k}: {v}, {current_path}, {match_path}")
                    else:
                        src[k] = v
                else:
                    src[k] = value
                    print(f"Match found: {k}: {v}, {current_path}, {match_path}")
            else:
                continue
            current_path.pop()
        return src

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

    def find_replace(self, dataset=None, updates=None):
        """
        bcfortiapi.tools.toolbox.find_replace\n

        Inputs:
        -------\n
            *Dataset (dictionary or list - can contain nested list/dictionary objects), Updates (List of key/value pairs - eg. [{'key1': newvalue1}, {'key2': newvalue2}])*

        Functions:
        ----------\n
            *Find all instances of specified key within dataset and replace existing value with specified value*

        """
        if dataset is not None:
            if updates is not None:
                if type(updates) == dict:
                    for search_key, new_value in dict(updates).items():
                        if type(new_value) == list:
                            if len(new_value) == 2:
                                nv_value = new_value[0]
                                nv_path = list(new_value[1])
                                nv_path.append(search_key)
                                try:
                                    if type(dataset) == dict:
                                        dataset = self._dict_itr(src=dataset, key=search_key, value=nv_value, match_path=nv_path)
                                    elif type(dataset) == list:
                                        dataset = self._list_itr(src=dataset, key=search_key, value=nv_value, match_path=nv_path)
                                    else:
                                        self._debugger(fnct=self.find_replace.__name__, data={'ERR': 'Dataset object is not a valid Python list or dictionary'})
                                except Exception as error:
                                    self._debugger(fnct=self.find_replace.__name__, data={'ERR': str(error)})
                            else:
                                self._debugger(fnct=self.find_replace.__name__, data={'ERR': f'Updates entry contains a list object of invalid length - {str(len(new_value))}'})
                        else:
                            try:
                                if type(dataset) == dict:
                                    dataset = self._dict_itr(src=dataset, key=search_key, value=new_value, match_path=None)
                                elif type(dataset) == list:
                                    dataset = self._list_itr(src=dataset, key=search_key, value=new_value, match_path=None)
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