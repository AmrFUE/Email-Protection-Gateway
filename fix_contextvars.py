"""
Replace contextvars log capture with simple add/remove handler approach.
Works across thread boundaries (thread pool executors).
"""

def patch_malware():
    path = "EPG/malware-scanner/api_server.py"
    with open(path, "r") as f:
        content = f.read()

    # Remove contextvars imports and class
    content = content.replace(
        "import contextvars\nimport io\n\nrequest_log_buffer = contextvars.ContextVar('request_log_buffer', default=None)\n\nclass ContextLogHandler(logging.Handler):\n    def emit(self, record):\n        buf = request_log_buffer.get()\n        if buf is not None:\n            buf.write(self.format(record) + \"\\n\")\n\n# Attach to root logger so it captures unified_scanner logs too\nctx_handler = ContextLogHandler()\nctx_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))\nlogging.getLogger().addHandler(ctx_handler)\n",
        "import io\n\ndef _make_log_capture():\n    \"\"\"Create a StringIO buffer + handler. Works across threads unlike contextvars.\"\"\"\n    buf = io.StringIO()\n    handler = logging.StreamHandler(buf)\n    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))\n    handler.setLevel(logging.DEBUG)\n    return buf, handler\n"
    )

    # scan_file: replace buf/token setup
    content = content.replace(
        "        buf = io.StringIO()\n        token = request_log_buffer.set(buf)\n        logger.info(f\"Scanning: {file.filename} ({len(content):,} bytes)\")\n        try:",
        "        buf, _log_handler = _make_log_capture()\n        logging.getLogger().addHandler(_log_handler)\n        logger.info(f\"Scanning: {file.filename} ({len(content):,} bytes)\")\n        try:"
    )
    content = content.replace(
        "                \"logs\": buf.getvalue()\n            }\n        finally:\n            request_log_buffer.reset(token)",
        "                \"logs\": buf.getvalue()\n            }\n        finally:\n            logging.getLogger().removeHandler(_log_handler)"
    )

    # scan_eml: replace buf/token setup
    content = content.replace(
        "    buf = io.StringIO()\n    token = request_log_buffer.set(buf)\n    try:\n        logger.info(f\"Malware Scanner: Processing EML {file.filename}\")",
        "    buf, _log_handler = _make_log_capture()\n    logging.getLogger().addHandler(_log_handler)\n    try:\n        logger.info(f\"Malware Scanner: Processing EML {file.filename}\")"
    )
    content = content.replace(
        "            \"logs\": buf.getvalue()\n        }\n\n    except Exception as e:\n        logger.error(f\"EML scan failed: {e}\")\n        raise HTTPException(status_code=500, detail=f\"EML scan failed: {str(e)}\")\n\n    finally:\n        request_log_buffer.reset(token)\n        shutil.rmtree(tmp_dir, ignore_errors=True)",
        "            \"logs\": buf.getvalue()\n        }\n\n    except Exception as e:\n        logger.error(f\"EML scan failed: {e}\")\n        raise HTTPException(status_code=500, detail=f\"EML scan failed: {str(e)}\")\n\n    finally:\n        logging.getLogger().removeHandler(_log_handler)\n        shutil.rmtree(tmp_dir, ignore_errors=True)"
    )

    # Fix early-return early exit in scan_eml (before final return, also has logs field)
    content = content.replace(
        "                \"logs\": buf.getvalue()\n            }\n\n        # Scan each attachment",
        "                \"logs\": buf.getvalue()\n            }\n\n        # Scan each attachment"
    )

    with open(path, "w") as f:
        f.write(content)
    print(f"Patched {path}")


def patch_spam():
    path = "EPG/spam-filter/Spam/api_server.py"
    with open(path, "r") as f:
        content = f.read()

    content = content.replace(
        "import contextvars\nimport io\n\nrequest_log_buffer = contextvars.ContextVar('request_log_buffer', default=None)\n\nclass ContextLogHandler(logging.Handler):\n    def emit(self, record):\n        buf = request_log_buffer.get()\n        if buf is not None:\n            buf.write(self.format(record) + \"\\n\")\n\nctx_handler = ContextLogHandler()\nctx_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))\nlogging.getLogger().addHandler(ctx_handler)\n",
        "import io\n\ndef _make_log_capture():\n    buf = io.StringIO()\n    handler = logging.StreamHandler(buf)\n    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))\n    handler.setLevel(logging.DEBUG)\n    return buf, handler\n"
    )

    content = content.replace(
        "        buf = io.StringIO()\n        token = request_log_buffer.set(buf)\n        logger.info(f\"Scanning: {file.filename} ({len(content)} bytes)\")",
        "        buf, _log_handler = _make_log_capture()\n        logging.getLogger().addHandler(_log_handler)\n        logger.info(f\"Scanning: {file.filename} ({len(content)} bytes)\")"
    )
    content = content.replace(
        "        return {\"verdict\": verdict, \"score\": score, \"note\": note, \"details\": details, \"logs\": buf.getvalue()}\n\n    except Exception as e:\n        logger.error(f\"Scan failed: {e}\", exc_info=True)\n        raise HTTPException(status_code=500, detail=f\"Scan error: {type(e).__name__}: {e}\")\n    finally:\n        try:\n            request_log_buffer.reset(token)\n        except NameError:\n            pass\n        if tmp_path and os.path.exists(tmp_path):",
        "        return {\"verdict\": verdict, \"score\": score, \"note\": note, \"details\": details, \"logs\": buf.getvalue()}\n\n    except Exception as e:\n        logger.error(f\"Scan failed: {e}\", exc_info=True)\n        raise HTTPException(status_code=500, detail=f\"Scan error: {type(e).__name__}: {e}\")\n    finally:\n        try:\n            logging.getLogger().removeHandler(_log_handler)\n        except NameError:\n            pass\n        if tmp_path and os.path.exists(tmp_path):"
    )

    with open(path, "w") as f:
        f.write(content)
    print(f"Patched {path}")


def patch_phishing():
    path = "EPG/phishing-filter/phishing-filter-service/api_server.py"
    with open(path, "r") as f:
        content = f.read()

    content = content.replace(
        "import logging\nimport contextvars\nimport io\n\nrequest_log_buffer = contextvars.ContextVar('request_log_buffer', default=None)\n\nclass ContextLogHandler(logging.Handler):\n    def emit(self, record):\n        buf = request_log_buffer.get()\n        if buf is not None:\n            buf.write(self.format(record) + \"\\n\")\n\nctx_handler = ContextLogHandler()\nctx_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))\nlogging.getLogger().addHandler(ctx_handler)\n",
        "import logging\nimport io\n\ndef _make_log_capture():\n    buf = io.StringIO()\n    handler = logging.StreamHandler(buf)\n    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))\n    handler.setLevel(logging.DEBUG)\n    return buf, handler\n"
    )

    content = content.replace(
        "    temp_file_path = None\n    buf = io.StringIO()\n    token = request_log_buffer.set(buf)\n    try:",
        "    temp_file_path = None\n    buf, _log_handler = _make_log_capture()\n    logging.getLogger().addHandler(_log_handler)\n    try:"
    )
    content = content.replace(
        "            \"logs\": buf.getvalue()\n        }\n\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=f\"Phishing scan failed: {str(e)}\")\n        \n    finally:\n        try:\n            request_log_buffer.reset(token)\n        except NameError:\n            pass\n        # Securely clean up the temp file",
        "            \"logs\": buf.getvalue()\n        }\n\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=f\"Phishing scan failed: {str(e)}\")\n        \n    finally:\n        try:\n            logging.getLogger().removeHandler(_log_handler)\n        except NameError:\n            pass\n        # Securely clean up the temp file"
    )

    with open(path, "w") as f:
        f.write(content)
    print(f"Patched {path}")


patch_malware()
patch_spam()
patch_phishing()
