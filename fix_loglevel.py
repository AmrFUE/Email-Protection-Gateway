"""Apply root_logger.setLevel(INFO) fix to malware and spam scanners."""

def fix_file(path, old, new):
    with open(path, "r") as f:
        content = f.read()
    if old in content:
        content = content.replace(old, new)
        with open(path, "w") as f:
            f.write(content)
        print(f"Fixed: {path}")
    else:
        print(f"Pattern not found in: {path}")

# Malware scan_file
fix_file(
    "EPG/malware-scanner/api_server.py",
    "        buf, _log_handler = _make_log_capture()\n        logging.getLogger().addHandler(_log_handler)",
    "        buf, _log_handler = _make_log_capture()\n        logging.getLogger().setLevel(logging.INFO)\n        logging.getLogger().addHandler(_log_handler)"
)

# Malware scan_eml
fix_file(
    "EPG/malware-scanner/api_server.py",
    "    buf, _log_handler = _make_log_capture()\n    logging.getLogger().addHandler(_log_handler)",
    "    buf, _log_handler = _make_log_capture()\n    logging.getLogger().setLevel(logging.INFO)\n    logging.getLogger().addHandler(_log_handler)"
)

# Spam scan
fix_file(
    "EPG/spam-filter/Spam/api_server.py",
    "        buf, _log_handler = _make_log_capture()\n        logging.getLogger().addHandler(_log_handler)",
    "        buf, _log_handler = _make_log_capture()\n        logging.getLogger().setLevel(logging.INFO)\n        logging.getLogger().addHandler(_log_handler)"
)
