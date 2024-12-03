import re
import csv
from collections import defaultdict, Counter


def parse_log_file(file_path):
    """
    Parses the log file and extracts IP addresses, endpoints, and failed login attempts.
    :param file_path: Path to the log file
    :return: Tuple containing IP address counts, endpoint counts, and failed login attempts
    """
    ip_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)

    # Regular expressions for parsing
    ip_regex = r'^(\d{1,3}(?:\.\d{1,3}){3})'
    endpoint_regex = r'\"(?:GET|POST|PUT|DELETE|PATCH|HEAD) (/\S*)'
    failed_login_regex = r'401|Invalid credentials'

    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(ip_regex, line)
            if ip_match:
                ip = ip_match.group(1)
                ip_counts[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(endpoint_regex, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counts[endpoint] += 1

            # Detect failed login attempts
            if re.search(failed_login_regex, line):
                if ip_match:
                    failed_logins[ip] += 1

    return ip_counts, endpoint_counts, failed_logins


def save_to_csv(file_name, ip_counts, most_accessed, suspicious_activity):
    """
    Saves the results to a CSV file.
    :param file_name: Output CSV file name
    :param ip_counts: Dictionary of IP request counts
    :param most_accessed: Most accessed endpoint data
    :param suspicious_activity: Dictionary of suspicious activity
    """
    with open(file_name, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write IP requests per IP section
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write most accessed endpoint section
        writer.writerow([])
        writer.writerow(['Most Frequently Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Write suspicious activity section
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


def main():
    # File paths
    log_file = 'sample.log'
    output_file = 'log_analysis_results.csv'

    # Parse the log file
    ip_counts, endpoint_counts, failed_logins = parse_log_file(log_file)

    # Determine the most accessed endpoint
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])

    # Detect suspicious activity
    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > 0}

    # Display results
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_to_csv(output_file, ip_counts, most_accessed_endpoint, suspicious_activity)
    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    main()
