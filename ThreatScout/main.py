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
from engine.pe_analysis import analyze_pe_sections


# Thresholds & scoring
LOG_SCORE_THRESHOLD = 10
SCORING = {
    "high_entropy": 30,
    "packed_section": 30,
    "pe_file": 10,
    "signed": -10, #reduces suspicion! see: get_publisher
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
def scan_file(file_path):
    """
    Scans a file and returns a result dict safely for any file type.
    """
    result = {
        "path": file_path,
        "type": get_file_type(file_path),
        "hash": sha256_file(file_path),
        "entropy": None,
        "sections": [],
        "publisher": None,
    }

    # Always return a dict, even on failure
    if not result["type"] or not result["hash"]:
        return result

    # --------------------------
    # Entropy
    # --------------------------
    try:
        result["entropy"] = calculate_entropy(file_path)
    except Exception:
        result["entropy"] = None

    # --------------------------
    # PE-specific analysis
    # --------------------------
    if "PE32" in result["type"]:
        try:
            result["sections"] = analyze_pe_sections(file_path) or []
        except Exception:
            result["sections"] = []

        try:
            result["publisher"] = get_publisher(file_path)
        except Exception:
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
def score_result(result):
    """
    Calculate a suspicion score and reasons safely.
    Works for any file type, avoids NoneType issues.
    Returns: (score:int, reasons:list[str])
    """
    score = 0
    reasons = []

    # ----------------------------
    # Entropy-based scoring
    # ----------------------------
    entropy = result.get("entropy")
    if entropy is not None and entropy > 7.2:
        score += SCORING["high_entropy"]
        reasons.append(f"+{SCORING['high_entropy']} high file entropy")

    # ----------------------------
    # PE section analysis
    # ----------------------------
    for sec in result.get("sections") or []:
        if sec.get("entropy", 0) > 7.2 and sec.get("executable"):
            score += SCORING["packed_section"]
            reasons.append(
                f"+{SCORING['packed_section']} packed executable section ({sec.get('name','unknown')})"
            )
            break  # only one section needed

    # ----------------------------
    # PE file indicator
    # ----------------------------
    if "PE32" in result.get("type", ""):
        score += SCORING["pe_file"]
        reasons.append(f"+{SCORING['pe_file']} PE executable")

    # ----------------------------
    # Signed PE reduces score
    # ----------------------------
    publisher = result.get("publisher")
    if publisher:
        score += SCORING["signed"]  # negative reduces suspicion
        reasons.append(f"{SCORING['signed']} signed by {publisher}")

    # ----------------------------
    # Clamp score
    # ----------------------------
    score = max(0, min(100, score))

    return score, reasons

# --------------------------
# Helper: Verdict
# --------------------------
"""
More readable verdicts
"""
def classify_verdict(score, reasons, signed=False):
    high_entropy = any("entropy" in r.lower() for r in reasons)
    suspicious_sections = any("section" in r.lower() for r in reasons)

    if score >= 75:
        return "HIGH RISK – STRONG MALWARE INDICATORS"

    if high_entropy and signed:
        return "LIKELY PACKED BUT BENIGN"

    if score >= 40:
        return "SUSPICIOUS – MANUAL REVIEW RECOMMENDED"

    if signed and score < 20:
        return "LIKELY BENIGN – TRUSTED SIGNATURE"

    return "LIKELY BENIGN"

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
    MAIN ENTRY POINT
    """
    args = parse_args()
    max_workers = min(4, (os.cpu_count() or 4))

    # Collect files to scan
    all_files = list(walk_directory(args.path))
    total_files = len(all_files)

    # Create log file
    log_path = create_scan_log()
    with open(log_path, "w", encoding="utf-8") as log_file:
        log_file.write(f"Scan started: {datetime.now()}\n")
        log_file.write(f"Path scanned: {args.path}\n\n")

    # Thread pool & progress bar
    processed_files = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_file, f) for f in all_files}
        progress = tqdm(total=total_files, desc="Scanning", unit="file", ncols=80)

        # Process futures as they complete
        while futures:
            done, futures = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                result = future.result()
                if not result:
                    continue

                # Debug output
                print(f"{result['path']}")
                print(f"  Type    : {result['type']}")
                print(f"  Hash    : {result['hash']}")
                if result.get("entropy") is not None:
                    print(f"  Entropy : {result['entropy']}")
                if result.get("sections"):
                    for sec in result["sections"]:
                        print(
                            f"  Section : {sec.get('name','unknown')} | "
                            f"Entropy: {sec.get('entropy',0)} | "
                            f"Executable: {sec.get('executable',False)}"
                        )
                if result.get("publisher"):
                    print(f"  Publisher: {result['publisher']}")

                # Score & reasons
                score, reasons = score_result(result)
                verdict = classify_verdict(score, reasons, signed=bool(result.get("publisher")))

                # Thread-safe logging if score above threshold
                if score >= LOG_SCORE_THRESHOLD:
                    with log_lock:
                        with open(log_path, "a", encoding="utf-8") as log_file:
                            log_file.write(f"{result['path']}\n")
                            log_file.write(f"  Score   : {score}\n")
                            log_file.write(f"  Verdict : {verdict}\n")
                            for r in reasons:
                                log_file.write(f"  {r}\n")
                            log_file.write("\n")

                progress.update(1)
                processed_files += 1

        progress.close()

    # Final log entry
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write(f"Scan finished: {datetime.now()}\n")
        log_file.write(f"Total files processed: {processed_files}\n")

    print(f"\nScan log saved to: {log_path}")

if __name__ == "__main__":
    main()
