Log Analysis Script
This Python script processes log files to extract and analyze key information such as IP requests, endpoints, and suspicious activities. It is designed for cybersecurity-related tasks and demonstrates proficiency in file handling, string manipulation, and data analysis.

Features
Count Requests per IP Address

Extracts all IP addresses from the log file.
Counts and displays the number of requests per IP in descending order.
Identify the Most Frequently Accessed Endpoint

Analyzes endpoints accessed in the log file.
Displays the most accessed endpoint and its count.
Detect Suspicious Activity

Identifies brute force login attempts based on HTTP status codes (401) or failure messages like "Invalid credentials".
Flags IPs exceeding a configurable threshold (default: 10 failed attempts).
Output Results

Saves results to a CSV file (log_analysis_results.csv) with sections for IP request counts, endpoint access counts, and suspicious activity detection.
Requirements
Python 3.7+
Required libraries: collections, re, csv
