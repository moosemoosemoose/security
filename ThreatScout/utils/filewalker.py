import os

def walk_directory(root_path):
    import os

def walk_directory(root_path):
    """
    Safely walk a directory tree and yield file paths.
    Skips directories/files that cannot be accessed.
    """
    for root, dirs, files in os.walk(root_path, onerror=None):
        # Filter out directories we cannot access
        accessible_dirs = []
        for d in dirs:
            full_path = os.path.join(root, d)
            try:
                os.listdir(full_path)
                accessible_dirs.append(d)
            except (PermissionError, OSError):
                continue

        dirs[:] = accessible_dirs  # modify in-place for os.walk

        for file in files:
            file_path = os.path.join(root, file)
            try:
                yield file_path
            except (PermissionError, OSError):
                continue
