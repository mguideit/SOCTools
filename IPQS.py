import requests
from bs4 import BeautifulSoup
import sys


# This script depends on ipqualityscore.com and acts as: IP reputation checker
# No API is needed, the script scrape the content from ipqualityscore.com


if len(sys.argv) < 2:
  print("Usage: "+sys.argv[0]+" [IP]")
  print("Example: "+sys.argv[0]+" 8.8.8.8")
  exit()

IPQ = sys.argv[1]


def IPQS(IPQ):

	headers = {
	    'authority': 'www.ipqualityscore.com',
	    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	    'accept-language': 'en-US,en;q=0.9',
	    'cache-control': 'max-age=0',
	    'dnt': '1',
	    'sec-ch-ua-mobile': '?0',
	    'sec-fetch-dest': 'document',
	    'sec-fetch-mode': 'navigate',
	    'sec-fetch-site': 'none',
	    'sec-fetch-user': '?1',
	    'upgrade-insecure-requests': '1',
	}

	response = requests.get('https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/'+str(IPQ),headers=headers)

	BReply = BeautifulSoup(response.text, 'html.parser')
	Table = BReply.find("table")

	IP = Table.find_all("tr")[0].find_all("td")[1].text.strip()
	Country = Table.find_all("tr")[1].find_all("td")[1].find("span").text.strip()
	FraudScore = Table.find_all("tr")[2].find_all("td")[1].text.strip()
	MailSPAMBlockList = Table.find_all("tr")[3].find_all("td")[1].text.strip()
	ProxyVPNDetection = Table.find_all("tr")[4].find_all("td")[1].text.strip().replace("\t","").replace("\n", " - ")
	if "please use our API to query this IP address with a higher strictness level." in ProxyVPNDetection:
		ProxyVPNDetection = ProxyVPNDetection.replace(", please use our API to query this IP address with a higher strictness level","")
	IPHostname = Table.find_all("tr")[9].find_all("td")[1].text.strip()
	ISP = Table.find_all("tr")[10].find_all("td")[1].text.strip()
	ASN = Table.find_all("tr")[11].find_all("td")[1].text.strip()
	Organization = Table.find_all("tr")[12].find_all("td")[1].text.strip()
	IPCIDR = Table.find_all("tr")[16].find_all("td")[1].text.strip()

	FinalRes = {
		"IP":IP, 
		"Country":Country, 
		"FraudScore": FraudScore,
		"MailSPAMBlockList":MailSPAMBlockList,
		"ProxyVPNDetection":ProxyVPNDetection,
		"Hostname":IPHostname,
		"ISP":ISP,
		"ASN":ASN,
		"Organization":Organization,
		"CIDR":IPCIDR
	}

	return FinalRes


Q = IPQS(IPQ)
print(Q)



