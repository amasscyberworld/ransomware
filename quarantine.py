
import os
import shutil

def quarantine_file(file_path, quarantine_dir="quarantine"):
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
    filename = os.path.basename(file_path)
    quarantined_path = os.path.join(quarantine_dir, filename)
    shutil.move(file_path, quarantined_path)
    return quarantined_path
