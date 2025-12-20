import re
from pathlib import Path
def regex_range(input_text):
    pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:-(?:25[0-5]|2[0-4]\d|1?\d{1,2}))?\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:-(?:25[0-5]|2[0-4]\d|1?\d{1,2}))?$", re.IGNORECASE)
    return pattern.match(input_text)


def regex_ip(input_text):
    pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", re.IGNORECASE)
    return pattern.match(input_text)
'''
def regex_logfile(filename):
    pattern = re.compile(r".*\.(log|txt)$")
    return pattern.match(filename)

def regex_logfile(filename):
    pattern = re.compile(r".*\.(csv)$")
    return pattern.match(filename)
'''

def sanitize_file(file_path):
    allowed_extensions = ['.log', '.txt']
    file_name = Path(file_path.name)
    if file_name.suffix.lower() not in allowed_extensions:
        return None
    else:
        return file_name