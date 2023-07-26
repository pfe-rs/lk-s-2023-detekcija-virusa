#!/bin/python
import os
import re

logpath = "malware_logs_filtered"

def check_criteria(filepath):
    try:
        with open(filepath, "r") as file:
            content = file.read()
            # Does "parameter" appear anywhere in the file
            if "parameter" in content:
                return True
            # Does "killed by SIG", "terminated by SIG", or "stopped by SIG" appear in the last 5 lines of the file
            lines = content.splitlines()
            lines = lines[-5:]
            for line in lines:
                if re.search(r"(killed|terminated|stopped) by SIG(?!KILL|TERM)\w+", line):
                    return True
    except Exception as e:
        print(f"Error while processing {filepath}: {e}")

    return False

def remove_files(dirpath):
    filelist = os.listdir(dirpath)
    for filename in filelist:
        filepath = os.path.join(dirpath, filename)
        if os.path.isfile(filepath):
            if check_criteria(filepath):
                try:
                    os.remove(filepath)
                    print(f"Removed file: {filepath}")
                except Exception as e:
                    print(f"Error while removing {filepath}: {e}")

#########################################################################

remove_files(logpath)
