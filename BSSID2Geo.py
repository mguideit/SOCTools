import requests
import sys
import re


# This script takes BSSID as argument
# Return the geolocation


if len(sys.argv) < 2:
	print("Usage: "+sys.argv[0]+" [BSSID]")
	print("Example: "+sys.argv[0]+" 00:0C:42:1F:65:E9")
	exit()

BSSID = sys.argv[1]


if re.match("[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}", BSSID):
	r = requests.get("https://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&bssid="+BSSID)
	if r.status_code == 200:
		if r.json()["result"] == 200:
			map = "https://www.latlong.net/c/?lat="+str(r.json()['data']['lat'])+"&long="+str(r.json()["data"]['lon'])
			print("Latitude: " + str(r.json()['data']['lat']))
			print("Longtude: " + str(r.json()["data"]['lon']))
			print("Find Address on Map: " + map)
		else:
			print("BSSID Not Found!")
	else:
		print("Error Occured!")
else:
	print("Please Provide Valid BSSID Address, Example: 00:0C:42:1F:65:E9")

