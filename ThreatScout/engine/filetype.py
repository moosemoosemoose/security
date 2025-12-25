import magic

def get_file_type(file_path):
    '''
    Returns a human-readable file type string.
    Returns None if file type cannot be determined.
    '''

    try:
        ms = magic.Magic(mime=False)
        return ms.from_file(file_path)
    except Exception:
        return None