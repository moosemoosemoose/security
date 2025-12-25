import os

def walk_directory(root_path):
    '''
    Recursively walk through a directory and yield all its subdirectories.
    Skips directories/files it cannot access
    '''
    for root, dirs, files in os.walk(root_path):
        for name in files:
            yield os.path.join(root, name)