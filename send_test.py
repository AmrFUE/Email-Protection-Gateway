import smtplib
import sys
import os

if len(sys.argv) < 2:
    print("Usage: python send_test.py <path_to_eml_file>")
    sys.exit(1)

eml_file = sys.argv[1]
if not os.path.exists(eml_file):
    print(f"File not found: {eml_file}")
    sys.exit(1)

with open(eml_file, "rb") as f:
    email_data = f.read()

# Send directly to the EPG Bridge (which listens on port 25)
try:
    print(f"Sending {eml_file} to EPG Bridge on localhost:25...")
    with smtplib.SMTP("127.0.0.1", 25) as server:
        # We don't need to specify sender/receiver here, the bridge parses the .eml envelope
        server.sendmail("test@example.com", ["admin@jawabi.app"], email_data)
    print("Successfully injected into EPG Pipeline!")
except Exception as e:
    print(f"Error: {e}")
