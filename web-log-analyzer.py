import re
import csv
import json
from collections import Counter
from bs4 import BeautifulSoup

# 1. Log Data
logs = [
    '192.168.1.100 - - [05/Dec/2024:09:15:10 +0000] "GET http://malicious-site.com/page1 HTTP/1.1" 404 4321',
    '192.168.1.101 - - [05/Dec/2024:09:16:20 +0000] "GET http://example.com/page2 HTTP/1.1" 200 5432',
    '192.168.1.102 - - [05/Dec/2024:09:17:30 +0000] "GET http://blacklisteddomain.com/page3 HTTP/1.1" 404 1234',
    '192.168.1.103 - - [05/Dec/2024:09:18:40 +0000] "POST http://malicious-site.com/login HTTP/1.1" 404 2345'
]

# 2. HTML File Parsing
html_file = 'C:\\Users\\user\\Desktop\\lab2_extracted\\threat_feed.html'  # Path to your HTML file"

with open(html_file, 'r') as f:
    soup = BeautifulSoup(f, 'lxml')

# Find all links in the HTML file that contain blacklisted domains
blacklist_domains = [a['href'].replace('http://', '') for a in soup.find_all('a', href=True)]
print(f"Blacklisted Domains: {blacklist_domains}")

# 3. Extract URLs and Status Codes from the log file using regex
url_pattern = r'(?P<url>http[s]?://\S+)'
status_code_pattern = r'(?P<status_code>\d{3})'

url_status_list = []
for log in logs:
    url_match = re.search(url_pattern, log)
    status_code_match = re.search(status_code_pattern, log)

    if url_match and status_code_match:
        url_status_list.append({
            'url': url_match.group('url'),
            'status_code': status_code_match.group('status_code')
        })

# 4. Identify 404 status URLs and count occurrences
error_404_urls = [entry['url'] for entry in url_status_list if entry['status_code'] == '404']
url_counts = Counter(error_404_urls)

# 5. Compare URLs to Blacklist
blacklisted_urls = [entry for entry in url_status_list if any(domain in entry['url'] for domain in blacklist_domains)]

# 6. Write URL and Status Code report to 'url_status_report.txt'
with open('url_status_report.txt', 'w') as f:
    for entry in url_status_list:
        f.write(f"{entry['url']} {entry['status_code']}\n")

# 7. Write 404 URLs and their count to 'malware_candidates.csv'
with open('malware_candidates.csv', 'w', newline='') as csvfile:
    fieldnames = ['URL', '404 Count']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for url, count in url_counts.items():
        writer.writerow({'URL': url, '404 Count': count})

# 8. Write JSON alert file for blacklisted URLs
alert_data = [{'url': url['url'], 'status_code': url['status_code'], 'event_count': url_counts[url['url']]}
              for url in blacklisted_urls]

with open('alert.json', 'w') as json_file:
    json.dump(alert_data, json_file, indent=4)

# 9. Write summary report as JSON file
summary_data = {
    'total_urls': len(url_status_list),
    '404_errors': len(error_404_urls),
    'unique_404_urls': len(url_counts),
    'blacklisted_matches': len(blacklisted_urls)
}

with open('summary_report.json', 'w') as json_file:
    json.dump(summary_data, json_file, indent=4)

print("Processing complete. Reports generated.")
