Run the script with the desired command-line arguments:

To check a single IP address, use the following command:

python ipcheck.py -ip <IP_ADDRESS>
Replace <IP_ADDRESS> with the IP address you want to check.

To check multiple IP addresses from a CSV file, use the following command:

python ipcheck.py -file <CSV_FILE_PATH>
Replace <CSV_FILE_PATH> with the path to the CSV file containing a list of IP addresses.

The script will start checking the IP reputation using various sources.

After processing, the script will generate a CSV file named ip_reputation_scores.csv in the same directory, containing the results.

Output:

The CSV output file (ip_reputation_scores.csv) will contain the following columns:

1. IP Address: The IP address that was checked.
2. VirusTotal Score: The VirusTotal score for the IP address.
3. IBM X-Force Score: The IBM X-Force score for the IP address.
4. AbuseIPDB Score: The reputation score from AbuseIPDB, categorized as "Safe ISP," "Blacklisted," or "Safe."
5. DNSBL Score: The DNSBL score for the IP address.
6. ISP: The Internet Service Provider associated with the IP address.
6. Country: The country where the IP address is located.