# bcfortiapi

A Python library for interacting with the Fortinet FortiGate and FortiManager APIs

## Current Status

- Status: Beta
- Latest Release: 0.9
- Release Date: 06-02-2026

## Dependencies

- Python 3: minimum supported version 3.11
- urllib3: minimum supported version 2.2.1
- requests: minimum supported version 2.32.3

## Usage Examples

### Initialisation

To initialise the library within your project add the following:

**FortiGate**

```
import bcfortiapi

init_variable = bcfortiapi.fgtapi(fortigate="FGT IP or FQDN", port="FGT HTTPS Admin Port", authtoken="FGT API Token", version="7.4", debug=True/False)
```
- fortigate (str) = IP address or FQDN of the target FortiGate
- port (str) = HTTPS admin port number of the target FortiGate
- authtoken (str) = FortiGate API administrator token (if using basic authentication, leave this field blank and use the *login* and *logout* functions instead)
- version (str) = Major and minor FortiOS version of the target FortiGate (eg. 7.4)
- debug (bool) = Console debug output enabled

**FortiManager**

```
import bcfortiapi

init_variable = bcfortiapi.fmgapi(server="127.0.0.1", port="443", version="7.4", debug=False)
```
- server (str) = IP address or FQDN of the target FortiManager
- port (str) = HTTPS admin port number of the target FortiManager
- version (str) = Major and minor configuration database version of the target FortiManager (eg. 7.4)
- debug (bool) = Console debug output enabled

### General Usage

**FortiGate**

*Login (Basic Authentication Only)*
```
init_variable.login(username="Username", password="Password")
```
    
*Login and return login state (bool)*
```
response_variable = init_variable.login(username="Username", password="Password")
```

*Example GET (response returned as JSON-formatted string, can be read using json.loads)*
```
response_variable = init_variable.dvmdb_device(adom="ADOM name", method="get")
```

*Example GET (with URL options)*
```
response_variable = init_variable.dvmdb_device(adom="ADOM name", method="get", urloptions="vdom=root&search=string")
```

*Logout (Basic Authentication Only)*
```
init_variable.logout()
```

**FortiManager**

*Login*
```
init_variable.login(username="Username", password="Password")
```

*Login and return login state (bool)*
```
response_variable = init_variable.login(username="Username", password="Password")
```

*Example GET (response returned as JSON-formatted string, can be read using json.loads)*
```
response_variable = init_variable.dvmdb_device(adom="ADOM name", method="get")
```

*Logout*
```
init_variable.logout()
```

## Change Log 0.9

- 06-02-2026: Fixed bug where JSON response containing boolean values could not be read by Python JSON module due to capitalised True/False values in response
- 06-02-2026: Initial release

## Change Log 0.8

- 04-02-2026: Initial release
