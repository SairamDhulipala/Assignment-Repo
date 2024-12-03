
# **Log Analysis Script**

## **Overview**
This Python script processes log files to extract and analyze key information. Designed for cybersecurity-related tasks, the script demonstrates proficiency in file handling, string manipulation, and data analysis.

---

## **Features**

1. **Count Requests per IP Address**  
   - Parses the log file to extract and count requests from each IP address.
   - Displays the results in descending order of request counts.

2. **Identify the Most Frequently Accessed Endpoint**  
   - Extracts endpoints (e.g., URLs) and identifies the one accessed the most, along with its count.

3. **Detect Suspicious Activity**  
   - Flags potential brute force login attempts by identifying IPs with failed login attempts exceeding a configurable threshold (default: 10 attempts).

4. **Results Output**  
   - Displays results in the terminal in a structured format.
   - Saves the output to a CSV file (`log_analysis_results.csv`) with three sections:
     - Requests per IP
     - Most Accessed Endpoint
     - Suspicious Activity

---

## **Installation**

1. **Prerequisites**
   - Python 3.7 or higher installed on your system.
   - A log file (e.g., `sample.log`) to analyze.

2. **Clone the Repository**
   ```bash
   git clone https://github.com/SairamDhulipala/Assignment-Repo.git
   cd Assignment-Repo
   ```

3. **Install Dependencies**
   - If additional libraries are required (e.g., `pandas` for CSV operations):
     ```bash
     pip install pandas
     ```

---

## **Usage**

1. Place the log file (e.g., `sample.log`) in the script directory.
2. Run the script:
   ```bash
   python vrv.py
   ```
3. The results will:
   - Be displayed in the terminal.
   - Be saved to `log_analysis_results.csv`.

---

## **Configuration**

### Modify the **Failed Login Threshold**
The default threshold for detecting suspicious login attempts is 10. You can change this by editing the following line in the script:
```python
FAILED_LOGIN_THRESHOLD = 10
```

---

## **Output Example**

### **Terminal Output**
```plaintext
IP Address           Request Count
192.168.1.1          234
203.0.113.5          187

Most Frequently Accessed Endpoint:
/home (Accessed 403 times)

Suspicious Activity Detected:
IP Address           Failed Login Attempts
192.168.1.100        56
203.0.113.34         12
```

### **CSV Output**
The `log_analysis_results.csv` will have the following sections:
1. Requests per IP  
   Columns: `IP Address`, `Request Count`
2. Most Accessed Endpoint  
   Columns: `Endpoint`, `Access Count`
3. Suspicious Activity  
   Columns: `IP Address`, `Failed Login Count`

---

## **Sample Log File**

Save the following content as `sample.log`:
```plaintext
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256
```

---