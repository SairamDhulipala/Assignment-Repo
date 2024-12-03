import csv
from collections import Counter


LOG_FILE = "VRV sample.log"
OUTPUT_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10  # This is set to prevent brute force attempts and can be changed.


def parse_log_file(log_file): #This function rads the log file line by line to extract IPs, endpoints, and suspicious activity.
    
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = Counter()

    with open(log_file, "r") as file:
        for line in file:
            parts = line.split()
            if len(parts) < 9:
                continue  

            ip = parts[0]
            endpoint = parts[6]
            status_code = parts[8]
            failure_message = " ".join(parts[9:])
            ip_requests[ip] += 1
            endpoint_requests[endpoint] += 1
            if status_code == "401" or "Invalid credentials" in failure_message:
                failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins


def save_results_to_csv(ip_requests, endpoint_requests, failed_logins, output_file): #This function saves the results to a new CSV file.
    
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])
        writer.writerow([])  
        writer.writerow(["Most Frequently Accessed Endpoint"])
        most_accessed_endpoint, access_count = endpoint_requests.most_common(1)[0]
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint, access_count])
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])


def display_results(ip_requests, endpoint_requests, failed_logins):
    print("=== Requests per IP Address ===")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count:<15}")
    print()

    print("=== Most Frequently Accessed Endpoint ===")
    most_accessed_endpoint, access_count = endpoint_requests.most_common(1)[0]
    print(f"{most_accessed_endpoint} (Accessed {access_count} times)")
    print()

    print("=== Suspicious Activity Detected ===")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20} {count:<20}")
    print()


def main():
    print("Starting log analysis...\n")
    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)
    print("Log Analysis Results:")
    display_results(ip_requests, endpoint_requests, failed_logins)
    print(f"Saving results to {OUTPUT_FILE}...")
    save_results_to_csv(ip_requests, endpoint_requests, failed_logins, OUTPUT_FILE)
    print(f"Results successfully saved to {OUTPUT_FILE}.\n")
    print("Log analysis completed.")

if __name__ == "__main__":
    main()