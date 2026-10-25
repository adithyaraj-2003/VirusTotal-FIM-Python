import os
import hashlib
import time
import requests
from pathlib import Path

# Configuration
API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
WATCH_DIRECTORY = "./monitored_folder"
API_URL = "https://www.virustotal.com/api/v3/files/"

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def check_virustotal(file_hash):
    headers = {"x-apikey": API_KEY}
    response = requests.get(API_URL + file_hash, headers=headers)
    
    if response.status_code == 200:
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        return malicious_count
    elif response.status_code == 404:
        return 0  # Hash not found in VT database (clean or unknown file)
    else:
        print(f"API Error: Status code {response.status_code}")
        return None

def monitor_folder():
    print(f"[*] Starting File Integrity Monitor... Watching: {WATCH_DIRECTORY}")
    Path(WATCH_DIRECTORY).mkdir(exist_ok=True)
    
    known_files = {}
    
    # Initial scan of existing files
    for filepath in Path(WATCH_DIRECTORY).iterdir():
        if filepath.is_file():
            file_hash = calculate_sha256(filepath)
            if file_hash:
                known_files[str(filepath)] = file_hash

    print("[*] Baseline established. Monitoring for modifications and new files...\n")
    
    try:
        while True:
            current_files = {}
            for filepath in Path(WATCH_DIRECTORY).iterdir():
                if filepath.is_file():
                    path_str = str(filepath)
                    current_files[path_str] = calculate_sha256(filepath)

            # Check for new or modified files
            for path_str, file_hash in current_files.items():
                if path_str not in known_files:
                    print(f"[!] NEW FILE DETECTED: {path_str}")
                    analyze_file(path_str, file_hash)
                elif known_files[path_str] != file_hash:
                    print(f"[!] FILE MODIFIED: {path_str}")
                    analyze_file(path_str, file_hash)

            known_files = current_files
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\n[*] Stopping File Integrity Monitor.")

def analyze_file(file_path, file_hash):
    print(f"    - Computed SHA-256: {file_hash}")
    print(f"    - Querying VirusTotal API...")
    malicious_detections = check_virustotal(file_hash)
    
    if malicious_detections is not None:
        if malicious_detections > 0:
            print(f"    [!] ALERT: Flagged by {malicious_detections} security vendor(s) on VirusTotal!")
        else:
            print(f"    [+] Result: File appears clean (0 malicious detections).")
    print("-" * 50)

if __name__ == "__main__":
    monitor_folder()