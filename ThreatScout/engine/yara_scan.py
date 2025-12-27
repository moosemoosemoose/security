import yara
import os

RULES_PATH = "signatures/yara_rules"

def load_yara_rules():
    """
    Compile all YARA rules from RULES_PATH.
    """
    rule_files = {}

    for filename in os.listdir(RULES_PATH):
        if filename.endswith((".yar", ".yara")):
            full_path = os.path.join(RULES_PATH, filename)
            rule_files[filename] = full_path

    if not rule_files:
        raise RuntimeError("No YARA rules found in RULES_PATH")

    return yara.compile(filepaths=rule_files)


def scan_with_yara(file_path, rules):
    """
    Scan a file with compiled YARA rules.
    Handles both binaries (PE, EXE) and text files reliably.

    Returns:
        list[str]: Names of matched rules
    """
    import os
    import yara

    try:
        # Make sure the file exists
        if not os.path.isfile(file_path):
            return []

        # Read file as binary
        with open(file_path, "rb") as f:
            data = f.read()

        # Use data= for both text and binary files to avoid encoding issues
        matches = rules.match(data=data)
        return [m.rule for m in matches]

    except yara.Error as e:
        print(f"YARA scan error on {file_path}: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error scanning {file_path}: {e}")
        return []


