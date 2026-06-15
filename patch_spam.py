import re

file_path = "EPG/spam-filter/Spam/api_server.py"
with open(file_path, "r") as f:
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

ctx_handler = ContextLogHandler()
ctx_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logging.getLogger().addHandler(ctx_handler)
"""
content = content.replace("import uvicorn", imports)

# 2. Modify scan endpoint
content = content.replace('        logger.info(f"Scanning: {file.filename} ({len(content)} bytes)")', 
'''        logger.info(f"Scanning: {file.filename} ({len(content)} bytes)")

        buf = io.StringIO()
        token = request_log_buffer.set(buf)''')

content = content.replace('''        return {"verdict": verdict, "score": score, "note": note, "details": details}

    except Exception as e:''', '''        return {"verdict": verdict, "score": score, "note": note, "details": details, "logs": buf.getvalue()}

    except Exception as e:''')

content = content.replace('    finally:\n        if tmp_path and os.path.exists(tmp_path):',
'''    finally:
        try:
            request_log_buffer.reset(token)
        except NameError:
            pass
        if tmp_path and os.path.exists(tmp_path):''')

with open(file_path, "w") as f:
    f.write(content)
