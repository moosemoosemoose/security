import math
from collections import Counter

READ_LIMIT = 1024 * 1024 # Up to 1MB

def calculate_entropy(file_path):
    '''
    Calculate Shannon entropy of a file.
    Returns entropy value or None on failure.
    '''

    try:
        with open(file_path, 'rb') as f:
            data = f.read(READ_LIMIT)

        if not data:
            return 0.0

        byte_counts = Counter(data)
        data_len = len(data)

        entropy = 0.0
        for count in byte_counts.values():
            p = count / data_len
            entropy -= p * math.log2(p)

        return round(entropy, 3)

    except (PermissionError, FileNotFoundError, OSError):
        return None
