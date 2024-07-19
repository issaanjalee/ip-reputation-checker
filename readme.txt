# README

## IP Reputation Checker

This script allows you to check the reputation of one or multiple IP addresses using various online sources. The results are saved in a CSV file for easy review.

### Prerequisites

- Python 3.x
- Required Python packages (install using `pip install -r requirements.txt`)

### Usage

#### Check a Single IP Address

To check a single IP address, use the following command:

```bash
python ipcheck.py -ip <IP_ADDRESS>
```

Replace `<IP_ADDRESS>` with the IP address you want to check.

#### Check Multiple IP Addresses from a CSV File

To check multiple IP addresses from a CSV file, use the following command:

```bash
python ipcheck.py -file <CSV_FILE_PATH>
```

Replace `<CSV_FILE_PATH>` with the path to the CSV file containing a list of IP addresses.

### Script Execution

The script will start checking the IP reputation using various sources. After processing, the script will generate a CSV file named `ip_reputation_scores.csv` in the same directory, containing the results.

### Output

The CSV output file (`ip_reputation_scores.csv`) will contain the following columns:

1. **IP Address:** The IP address that was checked.
2. **VirusTotal Score:** The VirusTotal score for the IP address.
3. **IBM X-Force Score:** The IBM X-Force score for the IP address.
4. **AbuseIPDB Score:** The reputation score from AbuseIPDB, categorized as "Safe ISP," "Blacklisted," or "Safe."
5. **DNSBL Score:** The DNSBL score for the IP address.
6. **ISP:** The Internet Service Provider associated with the IP address.
7. **Country:** The country where the IP address is located.

### Example

To check a single IP address:
```bash
python ipcheck.py -ip 192.168.1.1
```

To check multiple IP addresses from a CSV file:
```bash
python ipcheck.py -file ip_list.csv
```

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### Acknowledgements

- [VirusTotal](https://www.virustotal.com/)
- [IBM X-Force](https://exchange.xforce.ibmcloud.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [DNSBL](https://www.dnsbl.info/)
