import re

def regex_range(input_text):
    pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:-(?:25[0-5]|2[0-4]\d|1?\d{1,2}))?\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:-(?:25[0-5]|2[0-4]\d|1?\d{1,2}))?$", re.IGNORECASE)
    return pattern.match(input_text)


def regex_ip(input_text):
    pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", re.IGNORECASE)
    return pattern.match(input_text)