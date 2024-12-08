import re
import csv
from collections import defaultdict

# Function to parse the log file
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

# Function to count requests per IP
def count_requests_per_ip(logs):
    ip_counts = defaultdict(int)
    for log in logs:
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)", log)
        if match:
            ip_counts[match.group(1)] += 1
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

# Function to find the most accessed endpoint
def find_most_accessed_endpoint(logs):
    endpoint_counts = defaultdict(int)
    for log in logs:
        match = re.search(r"\"[A-Z]+\s(/[\w/]+)\sHTTP", log)
        if match:
            endpoint_counts[match.group(1)] += 1
    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1], default=None)
    return most_accessed

# Function to detect suspicious activity
def detect_suspicious_activity(logs, threshold=10):
    failed_attempts = defaultdict(int)
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)", log)
            if match:
                failed_attempts[match.group(1)] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

# Function to save results to a CSV file
def save_results_to_csv(ip_requests, most_accessed, suspicious_activity, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests)
        writer.writerow([])
        
        # Write most accessed endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        if most_accessed:
            writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])
        
        # Write suspicious activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity.items())

# Main function to execute the script
def main():
    log_file = "sample.log"  # Replace with your log file path
    output_file = "log_analysis_results.csv"
    
    logs = parse_log_file(log_file)
    
    # Analyze logs
    ip_requests = count_requests_per_ip(logs)
    most_accessed = find_most_accessed_endpoint(logs)
    suspicious_activity = detect_suspicious_activity(logs)
    
    # Display results
    print("Requests per IP:")
    for ip, count in ip_requests:
        print(f"{ip: <20} {count}")
    
    if most_accessed:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    if suspicious_activity:
        print("\nSuspicious Activity Detected:")
        for ip, count in suspicious_activity.items():
            print(f"{ip: <20} {count}")
    
    # Save results to CSV
    save_results_to_csv(ip_requests, most_accessed, suspicious_activity, output_file)
    print(f"\nResults saved to {output_file}")

# Run the script
if __name__ == "__main__":
    main()
