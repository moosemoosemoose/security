import pefile
import math
from collections import Counter

def calculate_entropy(data):
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)

def analyze_pe_sections(file_path):
    '''
    Analyze PE sections and return entropy per section.
    '''
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()

        results = []

        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00")
            data = section.get_data()
            entropy = calculate_entropy(data)

            results.append({
                "name": name,
                "entropy": entropy,
                "size": section.SizeOfRawData,
                "executable": bool(section.Characteristics & 0x20000000)
            })

        return results

    except pefile.PEFormatError:
        return None