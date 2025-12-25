import yara
import os

RULES_PATH = "signatures/yara_rules"

def load_yara_rules():
    '''
    Compile all YARA rules
    '''
    rules = {}

    for filename in os.listdir(RULES_PATH):
        if filename.endswith(".yar") or filename.endswith(".yara"):
            full_path = os.path.join(RULES_PATH, filename)
            rules[filename] = full_path

    return yara.compile(filepaths=rules)

def scan_with_yara(file_path, rules):
    '''
    Scan a file with compiled YARA rules.
    Returns a list of matched rule names.
    '''
    try:
        matches = rules.match(file_path)
        return [match.rule for match in matches]
    except yara.Error:
        return []