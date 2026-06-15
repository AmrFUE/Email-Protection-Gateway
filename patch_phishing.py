import re

file_path = "EPG/phishing-filter/phishing-filter-service/api_server.py"
with open(file_path, "r") as f:
    content = f.read()

# 1. Add imports and handler
imports = """import uvicorn
import logging
import contextvars
import io

request_log_buffer = contextvars.ContextVar('request_log_buffer', default=None)

class ContextLogHandler(logging.Handler):
    def emit(self, record):
        buf = request_log_buffer.get()
        if buf is not None:
            buf.write(self.format(record) + "\\n")

ctx_handler = ContextLogHandler()
ctx_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logging.getLogger().addHandler(ctx_handler)
"""
content = content.replace("import uvicorn", imports)

# 2. Modify scan endpoint
content = content.replace('''    temp_file_path = None
    try:''', 
'''    temp_file_path = None
    buf = io.StringIO()
    token = request_log_buffer.set(buf)
    try:''')

content = content.replace('''        return {
            "verdict": verdict,
            "score": score,
            "note": note,
            "details": details
        }''', '''        return {
            "verdict": verdict,
            "score": score,
            "note": note,
            "details": details,
            "logs": buf.getvalue()
        }''')

content = content.replace('''    finally:
        # Securely clean up the temp file
        if temp_file_path and os.path.exists(temp_file_path):''',
'''    finally:
        try:
            request_log_buffer.reset(token)
        except NameError:
            pass
        # Securely clean up the temp file
        if temp_file_path and os.path.exists(temp_file_path):''')

with open(file_path, "w") as f:
    f.write(content)
