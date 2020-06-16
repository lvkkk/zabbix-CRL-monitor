#!/usr/bin/env python3

zbxHost = {"host":"127.0.0.1"}
zbxHost["port"] = 80
zbxHost["trapperport"] = 10051
zbxHost["user"] = 'Admin'
zbxHost["pass"] = 'zabbix'
zbxHost["template"] = {"jsonrpc": "2.0", "id" : 0, "params" : {}}
zbxHost["path"] = "/api_jsonrpc.php"

import struct, json, re, socket 
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import urllib.request
import urllib.parse

params = {}
CRL = {}

def getTime(url):
  url = 'http://'+ url
  try:
    f = urllib.request.urlopen(url)
    crlData = f.read()
  except:
    print("CRL:\t", url, "\nDownload error!")
    return 0
  CRL = cryptography.x509.load_der_x509_crl(crlData, default_backend())
  return int(CRL.next_update.timestamp() - CRL.next_update.utcnow().timestamp())

def sendToZbx(zbxhost, host, key, timestamp):
  data='{"request":"sender data","data":[{"host":"'+ host +'","key":"'+ key +'","value":"' + str(timestamp) + '"}]}'
  print(data)
  packet = "ZBXD\1" + struct.pack('<Q', len(data)).decode('ascii') + data
  
  zabbix = socket.socket()
  try:
    zabbix.connect((zbxhost["host"], zbxhost["trapperport"]))
  except ImportError:
    print("Network exception")
  zabbix.sendall(packet.encode('ascii'))
  
  data = ''
  while True:
    packet = zabbix.recv(16)
    if not packet: break
    data += packet.decode('ascii')
  
  print(data)
  res_str = json.dumps(data, indent=4, separators=(',', ': '))
  zabbix.close()

def recieveall(zbxHost, method, params={}):
  altbody = json.dumps(getRequest(zbxHost, params, method),  separators=(',', ':'))
  body_bytes = altbody.encode('ascii')
  url = 'http://'+ zbxHost["host"] + ":" + str(zbxHost["port"]) + zbxHost["path"]
  req = urllib.request.Request(url, body_bytes)
  req.add_header("Content-Type", "application/json-rpc")
  req.add_header("Content-Length", str(len(body_bytes)))
  
  try:
    with urllib.request.urlopen(req) as response:
      resp = response.read()
  except:
    print("CRL:\t", url, "\nDownload error!")
    return 0
  return json.loads(resp.decode())

def getRequest(zbxHost, params, method):
  _params = zbxHost["template"]
  _params["params"] = params
  if (zbxHost["template"]["id"] == 0):
    _params["params"]["password"] = zbxHost["pass"]
    _params["params"]["user"] = zbxHost["user"]
    _params["method"] = "user.login"
  else:
    _params["method"] = method
  _params["id"] = zbxHost["template"]["id"]
  zbxHost["template"]["id"] += 1
  return _params

res = recieveall(zbxHost, "user.login")
if(len(res["result"])):
  zbxHost["template"]["auth"] = res["result"]
else:
  print("Login error!")
  quit(1)

#recieve hosts
params = {"output": ["id","name"], "tags": [{"tag": "crl", "value": "yes"}]} # "host.get"
res = recieveall(zbxHost, "host.get", params)
if (len(res["result"])):
  params = {"output": "extend", "hostids": []}
  for x in res["result"]:
    # ~ print (x)
    CRL[x["hostid"]] = {"name":x["name"]}
    params["hostids"].append(x["hostid"])
else:
  print("Error: No CRL!")
  quit(1)

#recieve macros
if (len(res["result"])):
  res = recieveall(zbxHost, "usermacro.get", params)
  for x in res["result"]:
    if (x["macro"] == "{$PATH}"):
      CRL[x["hostid"]]["path"] = x["value"]
else:
  print("Error: Set CRL path macro {$PATH}\
  /path/name.crl")
  quit(1)

params = {"output": ["hostid", 'useip', 'ip', 'dns', 'port'], "hostids": params["hostids"]}

#recieve host ip/dns, port
res = recieveall(zbxHost, "hostinterface.get", params)

if (len(res["result"])):
  for x in res["result"]:
    if (x["useip"] == "0"):
      CRL[x["hostid"]]["host"] = x["dns"]
    else:
      CRL[x["hostid"]]["host"] = x["ip"]
    CRL[x["hostid"]]["port"] = x["port"]
else:
  print("Error: No CRL interface")
  quit(1)

for x in CRL:
  try:
    sendToZbx(zbxHost, CRL[x]["name"], "exptime", getTime(CRL[x]["host"] + ":" + CRL[x]["port"] + CRL[x]["path"]))
  except:
    print("Send error!")

quit(0)

