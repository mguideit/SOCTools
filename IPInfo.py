import requests
from prettytable import PrettyTable
import sys
from bs4 import BeautifulSoup




# This script take file of IPs as argumnet
# Return information about each IP



if len(sys.argv) < 2:
  print("Usage: "+sys.argv[0]+" [IPs File]")
  print("Example: "+sys.argv[0]+" IPs.txt")
  exit()


IPsFile = sys.argv[1]




IPsTable = PrettyTable(["IP", "Organization","Country", "ISP"])
IPsTableB = PrettyTable(["IP", "PTR", "Bad Score /3"])

######################
# IP Info
######################

def IPInfo(IPsFile):
  with open(IPsFile) as file:
    IPs = file.readlines()
    for IP in IPs:
      print("Getting Info of: "+str(IP).rstrip())
      r = requests.get("http://ip-api.com/json/"+str(IP).rstrip())
      if r.json()["status"] == "success":
        IP = r.json()["query"]
        # City = r.json()["city"]
        # Region = r.json()["regionName"]
        Country = r.json()["country"]
        isp = r.json()["isp"]
        Organization = r.json()["org"]
        # Timezone = r.json()["timezone"]
        # stream = os.popen('host -t A ' + IP + ' | cut -d " " -f 5')
        # dns = stream.read()
        IPsTable.add_row([IP, Organization, Country, isp])
      else:
        print("Failed: "+str(IP).rstrip())
  IPsTable.sortby = "ISP"
  print("\n" + "#" * 20)
  print("IP Info: ")
  print("#" * 20 + "\n")
  print(IPsTable)


######################
# Threat Intel
######################

def BulkBlackList(IPsFile):
  BulkIPs = ''
  with open(IPsFile) as file:
    IPs = file.readlines()
    for IP in IPs:
      BulkIPs = BulkIPs + str(IP)
  payload = {'ips':BulkIPs}
  r = requests.post('https://www.bulkblacklist.com',data=payload, timeout=20)

  BReply = BeautifulSoup(r.text, 'html.parser')
  Table = BReply.find("table")
  for tr in Table.find_all("tr"):
    if tr.find_all('td')[1].text != 'IP':
      IP = tr.find_all('td')[1].text
      PTR = tr.find_all('td')[2].text
      Score = 0
      if 'r.png' in str(tr.find_all('td')[3].find('img')):
        Score = Score + 1
      elif 'r.png' in str(tr.find_all('td')[4].find('img')):
        Score = Score + 1
      elif 'r.png' in str(tr.find_all('td')[5].find('img')):
        Score = Score + 1
      IPsTableB.add_row([IP, PTR, Score])
  IPsTableB.sortby = "Bad Score /3"
  print("\n" + "#" * 20)
  print("Threat Intel: ")
  print("#" * 20 + "\n")
  print(IPsTableB)


IPInfo(IPsFile)
BulkBlackList(IPsFile)


























