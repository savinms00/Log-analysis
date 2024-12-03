import re
import csv
from collections import defaultdict
import os
import pandas as pd
from tabulate import tabulate

# Function to parse and extract the info
def parse_log(logfile_path):
    with open(logfile_path, 'r') as file:
        log_data = file.readlines()

    # Initialize counters
    ip_req_count = defaultdict(int)
    endpoint_count = defaultdict(int)
    failed_logins = defaultdict(int)

    for line in log_data:
        # Extracting IP address
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            ip_add = ip_match.group(1)
            ip_req_count[ip_add] += 1

        # Extracting endpoint
        endpoint_match = re.search(r'["](?:GET|POST) ([^ ]+)', line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_count[endpoint] += 1

        # Detecting failed logins
        if '401' in line or 'Invalid Credentials' in line:
            if ip_match:
                failed_logins[ip_add] += 1

    return ip_req_count, endpoint_count, failed_logins

# Function to write the results into CSV
def write_res_to_csv(ip_req_count, endpoint_count, failed_logins, output_file):
    with open(output_file, 'w', newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write IP request count
        writer.writerow(['------','Ip Request Count------'])
        writer.writerow(['ip_add', 'req_count'])
        for ip, count in sorted(ip_req_count.items(), key=lambda item: item[1], reverse=True):
            writer.writerow([ip, count])

        # Write most frequently accessed endpoint
        writer.writerow([])
        writer.writerow(['---------','Most frequently accessed endpoint --------'])
        if endpoint_count:
            most_end = max(endpoint_count.items(), key=lambda item: item[1])
            writer.writerow([most_end[0], most_end[1]])

        # Write suspicious activity (failed logins)
        writer.writerow([])
        writer.writerow(['-----Most suspicious activity detected:','----------'])
        for ip, count in failed_logins.items():
            writer.writerow([ip, count])

# File paths
logfile_path = r'C:\Users\savin\OneDrive\Desktop\log_analysis\sample.log'
output_file = 'log_analysis_results.csv'

# Calling function
ip_req_count, endpoint_count, failed_logins = parse_log(logfile_path)
write_res_to_csv(ip_req_count, endpoint_count, failed_logins, output_file)

print("Log analysis completed; Results have been saved to:", output_file)
df=pd.read_csv(output_file)
print(df)