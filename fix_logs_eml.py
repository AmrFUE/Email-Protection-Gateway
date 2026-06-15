import os

def move_buffer_up_eml(filepath, log_str):
    with open(filepath, "r") as f:
        content = f.read()

    replacement = f"""    buf = io.StringIO()
    token = request_log_buffer.set(buf)
    {log_str}"""

    target = f"""    {log_str}

    buf = io.StringIO()
    token = request_log_buffer.set(buf)"""
        
    if target in content:
        content = content.replace(target, replacement)
        with open(filepath, "w") as f:
            f.write(content)
        print(f"Fixed {filepath} (eml)")
    else:
        print(f"Target not found in {filepath} (eml)")

move_buffer_up_eml("EPG/malware-scanner/api_server.py", 'logger.info(f"EML Pipeline Scanning: {file.filename}")')
