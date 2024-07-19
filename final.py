import argparse
import csv
import re
import dns
import requests
import json
import base64
import urllib3
import config
import os 
import sys 
import dns.resolver
from config import urls

abuseipdb_url = 'https://api.abuseipdb.com/api/v2/check'
max_age_in_days = '120'  # Change this to the desired maximum age
def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text
    return '\x1b[%dm%s\x1b[0m' % (color_code, text)
def red(text):
    return color(text, 31)
def blink(text):
    return color(text, 5)
def green(text):
    return color(text, 32)
def blue(text):
    return color(text, 34)
def content_test(url, badip):
    try:
        request = urllib3.Request(url)
        opened_request = urllib3.build_opener().open(request)
        html_content = opened_request.read()
        retcode = opened_request.code

        matches = retcode == 200
        matches = matches and re.findall(badip, html_content)

        return len(matches) == 0
    except:
        return False
def query_abuseipdb(ip_address):
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': max_age_in_days,
        'verbose': 'yes'
    }

    headers = {
        'Accept': 'application/json',
        'Key': config.abuse_key,
    }

    response = requests.get(abuseipdb_url, headers=headers, params=querystring)
    return json.loads(response.text)
def ibm_xforce_ip_reputation(ip_address, api_key,api_password):
    auth_string = f"{api_key}:{api_password}"
    encoded_auth_string = base64.b64encode(auth_string.encode()).decode()
    headers = {"Authorization": f"Basic {encoded_auth_string}"}
    url = f"https://api.xforce.ibmcloud.com/ipr/{ip_address}"
    response = requests.get(url, headers=headers)
    data = response.json()
    #print(data.get("geo").get("country"))
    return [data.get("score"), data.get("cats"), data.get("geo").get("country")]

def virustotal_ip_reputation(ip_address, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    data = response.json()
    x=data.get("data", {}).get("attributes", {}).get("as_owner")
    return [x,data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious")]

#func for scoring of ips 
print("Checking the ip address on various listed urls")
def check_ip(ip, args):
    BAD = 0
    scores = {}
    for url, _, _, _ in config.urls:

        if content_test(url, ip):
            BAD += 1
            scores[url] = 1
        else:
            scores[url] = 0
    print("Checking Ip on trusted blacklisting platforms")
    print("Checking on DNSBL")
    for bl in config.bls:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(ip).split("."))) + "." + bl
            my_resolver.timeout = 10
            my_resolver.lifetime = 10
            answers = my_resolver.resolve(query, "A")  # Use resolve instead of query
            scores[bl] = 1
            BAD += 1

        except dns.resolver.NXDOMAIN:
            scores[bl] = 0

        except dns.resolver.Timeout:
            print(blink('WARNING: Timeout querying ' + bl))

        except dns.resolver.NoNameservers:
            print(blink('WARNING: No nameservers for ' + bl))

        except dns.resolver.NoAnswer:
            print(blink('WARNING: No answer for ' + bl))

    total_score = BAD
    return total_score
def main():
    parser = argparse.ArgumentParser(description="IP Reputation Checker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-ip", metavar="IP", help="Enter Comma separated IP addresses to check")
    group.add_argument("-file", metavar="FILE", help="Path to the input CSV file")
    args = parser.parse_args()

    if args.ip:
        print("Reading IP addresses from the command line argument")
        # Comma-separated IP addresses
        ip_addresses = args.ip.split(",")
    elif args.file:
        print("Reading IP addresses from the CSV file")
        # Read input from CSV file
        ip_addresses = []
        with open(args.file, "r") as file:
            reader = csv.reader(file)
            next(reader)  # Skip header row
            for row in reader:
                ip_addresses.append(row[0])

    results = []
    safe_isps = ["Google", "Microsoft", "Facebook"]

    for ip_address in ip_addresses:
        vt_score = virustotal_ip_reputation(ip_address, config.vt_api_key)
        xforce_score = ibm_xforce_ip_reputation(ip_address, config.xforce_api_key, config.xforce_api_password)
        abuseipdb_result = query_abuseipdb(ip_address)

        report_count = abuseipdb_result['data']['totalReports']
        isp = abuseipdb_result['data']['isp']
        # Check if the IP is from the safe ISP list and if not, check the count
        is_safe = 'Safe ISP' if isp in safe_isps else ('Blacklisted' if report_count >= 50 else 'Safe')
        country = abuseipdb_result['data']['countryName']

        # Calculate the DNSBL score using your existing code
        dnsbl_score = check_ip(ip_address, args)
        dnsbl_result = "Blacklisted" if dnsbl_score > 5 else "Safe"

        results.append({
            "IP Address": ip_address,
            "VirusTotal Score": vt_score[1],
            "IBM X-Force Score": xforce_score[0],
            "AbuseIPDB Score": is_safe,
            "DNSBL Score": dnsbl_score,
            #"Category": xforce_score[1],
            "ISP":vt_score[0],
            "Country": xforce_score[2],
            #"ISP": isp,
            #"dnsbl_result": dnsbl_result,
        })

    output_file = "ip_reputation_scores.csv"
    print("Checking IP addresses")

    with open(output_file, "w", newline="") as file:
        fieldnames = ["IP Address", "VirusTotal Score", "IBM X-Force Score", "AbuseIPDB Score","DNSBL Score","ISP","Country"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Results saved to '{output_file}' in the same directory.")

if __name__ == "__main__":
    main()
