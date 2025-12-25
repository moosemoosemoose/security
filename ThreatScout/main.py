"""
ThreatScout — Lightweight heuristic malware reconnaissance engine
Anthony Morris
"""
import argparse
import os
import struct
import subprocess
import re
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from tqdm import tqdm
import pefile
from utils.filewalker import walk_directory
from engine.hash_scan import sha256_file
from engine.filetype import get_file_type
from engine.entropy import calculate_entropy
from engine.yara_scan import load_yara_rules, scan_with_yara
from engine.pe_analysis import analyze_pe_sections


# Thresholds & scoring
LOG_SCORE_THRESHOLD = 50
SCORING = {
    "high_entropy": 30,
    "packed_section": 25,
    "yara_match": 20,
    "pe_file": 10,
    "signed": -15, #reduces suspicion! see: get_publisher
}

# Lock for thread-safe log writes
log_lock = threading.Lock()

def parse_args():
    """
    Parsin' them args
    """
    parser = argparse.ArgumentParser(
        description='ThreatScout malware scanner'
    )
    parser.add_argument(
        "-p", "--path",
        type=str,
        required=True,
        help="Path to scan (file or directory)"
    )
    return parser.parse_args()

# --------------------------
# Scanner
# --------------------------
def scan_file(file_path, yara_rules):
    """
    Scans the file
    """
    file_hash = sha256_file(file_path)
    file_type = get_file_type(file_path)

    if not file_hash or not file_type:
        return None

    result = {
        "path": file_path,
        "type": file_type,
        "hash": file_hash,
        "entropy": None,
        "yara": [],
        "sections": []
    }

    suspicious_entropy = False

    if "PE32" in file_type or "executable" in file_type.lower():
        entropy = calculate_entropy(file_path)
        result["entropy"] = entropy

        if entropy and entropy > 7.2:
            suspicious_entropy = True

    if suspicious_entropy:
        result["yara"] = scan_with_yara(file_path, yara_rules)

        sections = analyze_pe_sections(file_path)
        if sections:
            result["sections"] = [
                s for s in sections if s["entropy"] > 7.2
            ]

    publisher = None
    if "PE32" in file_type:
        publisher = get_publisher(file_path)
        if publisher:
            result["publisher"] = publisher
        else:
            result["publisher"] = None
    return result

# --------------------------
# Helper: wait for futures
# --------------------------
def wait_first(futures, log_file=None):
    """
    Thread pool traffic controller so we don't get a log jam.
    """
    done, pending = wait(futures, return_when=FIRST_COMPLETED)

    for future in done:
        result = future.result()
        if not result:
            continue

        # Print to console
        print(result["path"])
        print(f"  Type    : {result['type']}")
        print(f"  Hash    : {result['hash']}")
        if result.get("entropy") is not None:
            print(f"  Entropy : {result['entropy']}")
        if result.get("yara"):
            print(f"  YARA    : {', '.join(result['yara'])}")
        if result.get("sections"):
            for sec in result["sections"]:
                print(
                    f"  Section : {sec['name']} | "
                    f"Entropy: {sec['entropy']} | "
                    f"Executable: {sec['executable']} <-- suspicious"
                )

        # Compute score
        score_result(result, log_file=log_file)
    print()

    return done, pending

# --------------------------
# Helper: scoring function
# --------------------------
def score_result(result, log_file=None):
    """
    Calculates the scores
    """
    score = 0
    reasons = []

    # High entropy
    if result.get("entropy") and result["entropy"] > 7.2:
        score += SCORING["high_entropy"]
        reasons.append(f"+{SCORING['high_entropy']} high file entropy")

    # Sections
    if result.get("sections"):
        for sec in result["sections"]:
            if sec["entropy"] > 7.2 and sec["executable"]:
                score += SCORING["packed_section"]
                reasons.append(
                    f"+{SCORING['packed_section']} packed executable section ({sec['name']})"
                )
                break

    # YARA matches
    if result.get("yara"):
        score += SCORING["yara_match"]
        reasons.append(
            f"+{SCORING['yara_match']} YARA match(s): {', '.join(result['yara'])}"
        )

    # PE file
    if "PE32" in result.get("type", ""):
        score += SCORING["pe_file"]
        reasons.append(f"+{SCORING['pe_file']} PE executable")

    # Signed publisher reduces score
    if result.get("publisher"):
        score += SCORING["signed"]
        reasons.append(f"-{SCORING['signed']} signed by {result['publisher']}")

    # Clamp score 0-100
    score = max(0, min(100, score))

    # Thread-safe logging
    if score >= LOG_SCORE_THRESHOLD and log_file:
        with log_lock:
            with open(log_file, "a", encoding="utf-8") as log_file:
                log_file.write(f"{result['path']}\n")
                log_file.write(f"  Score: {score}\n")
                for r in reasons:
                    log_file.write(f"  {r}\n")
                log_file.write("\n")

    return score, reasons

# --------------------------
# Helper: Gets publisher of high scoring files
# --------------------------
def get_publisher(file_path):
    """
    Returns the publisher's common name if the file is signed, else None.
    Uses PowerShell Get-AuthenticodeSignature to extract signer info.
    """
    # Only check if the file exists and is a PE
    if not os.path.isfile(file_path):
        return None

    try:
        # PowerShell command to get the SignerCertificate.Subject
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"(Get-AuthenticodeSignature '{file_path}').SignerCertificate.Subject"
        ]

        # Run PowerShell safely
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=2,  # Prevent hanging
            creationflags=subprocess.CREATE_NO_WINDOW,
            check=False
        )

        # If PowerShell failed, return None
        if result.returncode != 0:
            return None

        publisher = result.stdout.strip()
        if not publisher:
            return None

        # Optional: extract CN= field for cleaner output
        match = re.search(r"CN=([^,]+)", publisher)
        return match.group(1) if match else publisher

    except subprocess.TimeoutExpired:
        # PowerShell took too long
        return None
    except (
        pefile.PEFormatError,
        AttributeError,
        ValueError,
        IndexError,
        PermissionError,
        OSError,
        struct.error,
    ):
        return None

# --------------------------
# Helper: create scan log
# --------------------------
def create_scan_log():
    """
    Tidy little log. Will save as MMDDYYYY then subsequent _1,_2...
    """
    date_str = datetime.now().strftime("%m%d%y")
    base_name = f"{date_str}Scan"
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{base_name}.log")
    counter = 1
    while os.path.exists(log_path):
        log_path = os.path.join(log_dir, f"{base_name}_{counter}.log")
        counter += 1
    return log_path

def main():
    """
    MAIN
    """
    args = parse_args()
    yara_rules = load_yara_rules()
    max_workers = min(4, (os.cpu_count() or 4))

    # Check out number of files for progress bar
    all_files = list(walk_directory(args.path))
    total_files = len(all_files)

    # Create log
    log_path = create_scan_log()
    with open(log_path, "w", encoding="utf-8") as log_file:
        log_file.write(f"Scan started: {datetime.now()}\n")
        log_file.write(f"Path scanned: {args.path}\n\n")


    processed_files = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = set()
        progress = tqdm(total=total_files, desc="Scanning", unit="file", ncols=80)

        for file_path in walk_directory(args.path):
            futures.add(executor.submit(scan_file, file_path, yara_rules))

            # Keep the queue bounded
            if len(futures) >= max_workers * 2:
                done, futures = wait_first(futures, log_file=log_file)
                progress.update(len(done))
                processed_files += len(done)

        # Drain remaining futures
        while futures:
            done, futures = wait_first(futures, log_file=log_file)
            progress.update(len(done))
            processed_files += len(done)

    progress.close()

    # Finish logging
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write(f"Scan finished: {datetime.now()}\n")

    print(f"\nScan log saved to: {log_path}")

if __name__ == "__main__":
    main()
