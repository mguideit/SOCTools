import requests
from prettytable import PrettyTable
import sys




# This script takes file of IPs as argument
# Returns information about each IP




if len(sys.argv) < 2:
  print("Usage: "+sys.argv[0]+" [IPs File]")
  print("Example: "+sys.argv[0]+" IPs.txt")
  exit()


IPsFile = sys.argv[1]




IPsTable = PrettyTable(["IP", "Organization","Country", "isp"])

def IPInfo(IP):
  r = requests.get("http://ip-api.com/json/"+str(IP))
  if r.json()["status"] == "success":
    IP = r.json()["query"]
    # City = r.json()["city"]
    # Region = r.json()["regionName"]
    Country = r.json()["country"]
    isp = r.json()["isp"]
    Organization = r.json()["org"]
    # Timezone = r.json()["timezone"]
    IPsTable.add_row([IP, Organization, Country, isp])
  else:
    print("Failed: "+str(IP).rstrip())






with open(IPsFile) as file:
  IPs = file.readlines()
  for IP in IPs:
    print("Getting Info of: "+str(IP).rstrip())
    IPInfo(str(IP).rstrip())



print("\nResult: ")
print(IPsTable)







