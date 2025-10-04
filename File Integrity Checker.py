import os
import hashlib
import json
from datetime import datetime

# Strong SHA-256 hashing for cybersecurity!
def get_file_hash(file_path):
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read in chunks for large files
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] {file_path}: {e}")
        return None

def scan_folder(folder_path):
    file_hashes = {}
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            hash_value = get_file_hash(file_path)
            if hash_value:
                file_hashes[file_path] = hash_value
    return file_hashes

def save_hashes(file_hashes, filename="hashes.json"):
    with open(filename, "w") as f:
        json.dump(file_hashes, f, indent=4)

def load_hashes(filename="hashes.json"):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return json.load(f)
    return {}

def check_integrity(folder_path, baseline_file="hashes.json"):
    print(f"[*] Scanning {folder_path} for file integrity at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ...")
    baseline_hashes = load_hashes(baseline_file)
    current_hashes = scan_folder(folder_path)

    compromised = False
    for file_path, curr_hash in current_hashes.items():
        orig_hash = baseline_hashes.get(file_path)
        if orig_hash and orig_hash != curr_hash:
            print(f"[ALERT] File changed: {file_path}")
            compromised = True
        elif not orig_hash:
            print(f"[INFO] New file detected: {file_path}")

    for file_path in baseline_hashes:
        if file_path not in current_hashes:
            print(f"[WARNING] File missing: {file_path}")
            compromised = True

    if not compromised:
        print("[SUCCESS] No unauthorized changes detected. All files secure.")

if __name__ == "__main__":
    folder_to_monitor = input("Enter folder path to monitor: ").strip()
    action = input("Type 'baseline' to create baseline or 'check' to verify integrity: ").strip().lower()

    if action == "baseline":
        print("[*] Creating baseline hash values...")
        hashes = scan_folder(folder_to_monitor)
        save_hashes(hashes)
        print("[*] Baseline saved to hashes.json.")
    elif action == "check":
        check_integrity(folder_to_monitor)
    else:
        print("[ERROR] Invalid action. Use 'baseline' or 'check'.")
