#bcfortiapi Test Program
#Created by Benjamin Court 15-02-2026
#Last Updated: 15-02-2026

#Description:
#------------
#FGT: Tests GET, POST, PUT and DELETE functions using webfilter profiles
#FMG: Tests GET, SET, ADD, DELETE and CLONE functions using webfilter profiles

#Requirements:
#-------------
#Set up the following webfilter profiles on the target FortiGate or FortiManager:
#   testprofile1 - set comment to "To be modified"
#   testprofile2 = set comment to "To be deleted"

#Expected Results:
#-----------------
#   All webfilter profiles returned as Python dictionary and printed to console
#   testprofile1 - comment set to "PROFILE MODIFIED"
#   testprofile2 - profile deleted
#   testprofile3 - profile created and comment set to "PROFILE CREATED"
#   testprofileclone - profile cloned from testprofile3 and comment set to "PROFILE CLONED" (FortiManager only)

import bcfortiapi

test_mode = "fmg" #Set to "fgt" for FortiGate or "fmg" for FortiManager

fgt_target_ip = "127.0.0.1"
fgt_target_port = "443"
token = ""
fgt_db_version = ""
backup_file = "c:\\fgt_test_backup.conf"

fmg_target_ip = "127.0.0.1"
fmg_target_port = "443"
target_adom = None
user = ""
passwd = ""
fmg_db_version = "7.4"

debug_enabled = True

def fortigate_test():
    #Initialise FortiManager API library
    fgt = bcfortiapi.fgtapi(fortigate=fgt_target_ip, port=fgt_target_port, authtoken=token, version=fgt_db_version, debug=debug_enabled)
    
    #Login
    if token is None:
        loginresponse = fgt.login(username=user, password=passwd)
    else:
        loginresponse = True
    if loginresponse == True:

        #GET Test
        getresponse = fgt.conf_webfilter_profile(method="get")
        print("GET Response - Configured Webfilter Profiles")
        print("--------------------------------------------")
        print(getresponse)
        print("")

        #PUT Test
        for i in range(len(getresponse['results'])):
            if getresponse['results'][i]['name'] == "testprofile1":
                getresponse['results'][i]['comment'] = "PROFILE MODIFIED"
                data_dict = getresponse['results'][i]
        fgt.conf_webfilter_profile(method="put", name="testprofile1", data=data_dict)

        #DELETE Test
        fgt.conf_webfilter_profile(method="delete", name="testprofile2")

        #POST Test
        data_dict = {
            "name": "testprofile3",
            "comment": "PROFILE CREATED"
        }
        fgt.conf_webfilter_profile(method="post", data=data_dict)

        #Non-JSON Response Test
        data_dict = {
            "destination": "file",
            "scope": "global",
            "file_format": "fos"
        }
        backup = fgt.mntr_system_config_backup(data=data_dict)
        with open(backup_file, "w") as file:
            file.write(str(backup, "utf-8"))
        file.close()

        fgt.logout()

    else:
        print("ERR: Login failed")
        print("")

def fortimanager_test():
    #Initialise FortiManager API library
    fmg = bcfortiapi.fmgapi(server=fmg_target_ip, port=fmg_target_port, debug=debug_enabled, version=fmg_db_version)

    #Login
    loginresponse = fmg.login(username=user, password=passwd)
    if loginresponse == True:

        #If ADOM specified, check if workspace mode enabled
        wsmode = False
        if target_adom is not None:
            wsmodecheck = fmg.dvmdb_adom(adom=target_adom, method="get")
            if wsmodecheck['result'][0]['data']['workspace_mode'] == 1:
                wsmode = True
            else:
                wsmode = False

            #If workspace mode enabled, check lock status
            if wsmode == True:
                response = fmg.dvmdb_workspace(adom=target_adom, action="info")
                if 'data' in str(response['result']):
                    print(f"ERR: ADOM locked by {str(response['result'][0]['data'][0]['lock_user'])}, exiting.")
                    fmg.logout()
                    quit()
                else:

                    #If ADOM unlocked, lock ADOM
                    fmg.dvmdb_workspace(adom=target_adom, action="lock")

        #Example GET - retrieve all webfilter profiles, use json.loads to convert JSON response to Python dictionary
        profiles = fmg.confdb_webfilter_profile(method="get", adom=target_adom)
        print("GET Response - Configured Webfilter Profiles")
        print("--------------------------------------------")
        print(profiles)
        print("")

        #Example SET to update existing webfilter profile
        data_dict = {
            "comment": "PROFILE MODIFIED"
        }
        fmg.confdb_webfilter_profile(adom=target_adom, profile="testprofile1", method="set", data=data_dict)

        #Example ADD to create new webfilter profile
        data_dict = {
            'name': 'testprofile3',
            'comment': 'PROFILE CREATED',
            'feature-set': 'flow'
        }
        fmg.confdb_webfilter_profile(adom=target_adom, method="add", data=data_dict)

        #Example DELETE to remove an existing webfilter profile
        fmg.confdb_webfilter_profile(adom=target_adom, profile="testprofile2", method="delete")

        #Example CLONE to duplicate an existing webfilter profile
        data_dict = {
            "name": "testprofileclone"
        }
        fmg.confdb_webfilter_profile(adom=target_adom, profile="testprofile3", method="clone", data=data_dict)
        data_dict = {
            "comment": "PROFILE CLONED"
        }
        fmg.confdb_webfilter_profile(adom=target_adom, profile="testprofileclone", method="set", data=data_dict)

        #If workspace mode enabled, commit changes and unlock ADOM
        if wsmode == True:
            fmg.dvmdb_workspace(adom=target_adom, action="commit")
            fmg.dvmdb_workspace(adom=target_adom, action="unlock")

        #Logout
        fmg.logout()

    else:
        print("ERR: Login failed")

if test_mode == "fgt":
    fortigate_test()
elif test_mode == "fmg":
    fortimanager_test()
else:
    print("ERR: Invalid test mode")
    print("")