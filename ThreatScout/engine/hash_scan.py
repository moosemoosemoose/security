import hashlib

BUFFER_SIZE = 65536 # 64KB

def sha256_file(file_path):
    '''
    Compute SHA-256 hash of a file.
    Returns None if file not found.
    '''

    sha256 = hashlib.sha256()

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(BUFFER_SIZE):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None