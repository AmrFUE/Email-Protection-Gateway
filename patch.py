import re

with open("EPG/malware-scanner/api_server.py", "r") as f:
    content = f.read()

# 1. Add imports and handler
imports = """import uvicorn
import contextvars
import io

request_log_buffer = contextvars.ContextVar('request_log_buffer', default=None)

class ContextLogHandler(logging.Handler):
    def emit(self, record):
        buf = request_log_buffer.get()
        if buf is not None:
            buf.write(self.format(record) + "\\n")

# Attach to root logger so it captures unified_scanner logs too
ctx_handler = ContextLogHandler()
ctx_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(ctx_handler)
"""
content = content.replace("import uvicorn", imports)

# 2. Modify scan_file
content = content.replace('        logger.info(f"Scanning: {file.filename} ({len(content):,} bytes)")', 
'''        logger.info(f"Scanning: {file.filename} ({len(content):,} bytes)")

        buf = io.StringIO()
        token = request_log_buffer.set(buf)''')

content = content.replace('''            "threat_intel": {
                "threat_level": result.get("threat_intel", {}).get("threat_level", "clean"),
                "threat_score": result.get("threat_intel", {}).get("threat_score", 0),
                "detections": result.get("threat_intel", {}).get("detections", []),
                "hash": result.get("threat_intel", {}).get("hashes", {}).get("sha256", ""),
            },
        }''', '''            "threat_intel": {
                "threat_level": result.get("threat_intel", {}).get("threat_level", "clean"),
                "threat_score": result.get("threat_intel", {}).get("threat_score", 0),
                "detections": result.get("threat_intel", {}).get("detections", []),
                "hash": result.get("threat_intel", {}).get("hashes", {}).get("sha256", ""),
            },
            "logs": buf.getvalue()
        }
        finally:
            request_log_buffer.reset(token)''')


# 3. Modify scan_eml
content = content.replace('    try:\n        with open(eml_path, \'wb\') as f:',
'''    buf = io.StringIO()
    token = request_log_buffer.set(buf)
    try:
        with open(eml_path, 'wb') as f:''', 1)

content = content.replace('''        return {
            "email": email_metadata,
            "headers": {
                "from": headers['from'],
                "to": headers['to'],
                "subject": headers['subject'],
                "spf_pass": headers['spf_pass'],
                "dkim_pass": headers['dkim_pass'],
                "dmarc_pass": headers['dmarc_pass'],
                "hop_count": headers['hop_count'],
            },
            "attachments": results,
            "urls": urls,
            "has_attachments": len(results) > 0,
            "has_urls": len(urls) > 0,
            "overall_verdict": worst_verdict,
            "overall_score": worst_score,
            "total_attachments": len(results),
            "total_urls": len(urls),
        }''', '''        return {
            "email": email_metadata,
            "headers": {
                "from": headers['from'],
                "to": headers['to'],
                "subject": headers['subject'],
                "spf_pass": headers['spf_pass'],
                "dkim_pass": headers['dkim_pass'],
                "dmarc_pass": headers['dmarc_pass'],
                "hop_count": headers['hop_count'],
            },
            "attachments": results,
            "urls": urls,
            "has_attachments": len(results) > 0,
            "has_urls": len(urls) > 0,
            "overall_verdict": worst_verdict,
            "overall_score": worst_score,
            "total_attachments": len(results),
            "total_urls": len(urls),
            "logs": buf.getvalue()
        }''')

content = content.replace('    finally:\n        shutil.rmtree(tmp_dir, ignore_errors=True)', '    finally:\n        request_log_buffer.reset(token)\n        shutil.rmtree(tmp_dir, ignore_errors=True)')

with open("EPG/malware-scanner/api_server.py", "w") as f:
    f.write(content)
