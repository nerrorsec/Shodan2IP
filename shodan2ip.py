import argparse
from shodan import Shodan

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--query", dest="query", help="Shodan query to perform")

def shodan_scan(query):
    print("[#] Performing Shodan Scan")
    api = Shodan('<YOUR-SHODAN-API-KEY>')
    data = {}
    for banner in api.search_cursor(query):
        port = banner["port"] 
        ip = banner["ip_str"]
        hostnames = banner["hostnames"]
        hostname = re.findall(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]", str(hostnames), flags=re.IGNORECASE)
        data[str(ip) + ':' + str(port)] = str(hostname)      
    f = open('IP_Domain_mapping___' + query + '.txt', 'w')
    f.write(str(data))
    f.close()
    f = open('IPs___' + query + '.txt', 'w')
    for key in data.keys():
            f.write(key + "\n")
    f.close()
    f_data = open('IP_Domain_mapping___' + query + '.txt', 'r')
    for key, value in ast.literal_eval(f_data.readlines()[0]).items():
        print(key + ": " + value)
    f_data.close()
    
options = get_arguments()
if options.query is not None:
  try:
    shodan_scan(options.query)
  except:
    print("[-] Something went wrong. Maybe your API key is not correct.")
else:
print("[-] Please specify an option.\nUse -h/--help for more details")
#nerrorsec #NSL
