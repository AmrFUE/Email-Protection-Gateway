import smtplib
from email.message import EmailMessage
import time
import sys

def send_test_email(email_type="clean"):
    msg = EmailMessage()
    msg['From'] = 'outside-hacker@evil.com'
    msg['To'] = 'admin@jawabi.app'
    msg['Date'] = time.strftime("%a, %d %b %Y %H:%M:%S %z")

    if email_type == "clean":
        msg['Subject'] = 'Hello from the outside world!'
        msg.set_content('This is a normal email. It should pass through the EPG and arrive in your inbox cleanly.')
    
    elif email_type == "spam":
        msg['Subject'] = 'YOU WON $1,000,000 DOLLARS!!!'
        msg.set_content('Reply with your bank details to claim your prize! Viagra! Cheap! Urgent!')
        
    elif email_type == "phishing":
        msg['Subject'] = 'URGENT: Your account is suspended'
        msg.set_content('Please click this link to verify your account immediately: http://evil-phishing-site.com/login')
        
    elif email_type == "malware":
        msg['Subject'] = 'Invoice Attached'
        msg.set_content('Please find the attached invoice.')
        # Add EICAR standard anti-virus test string
        eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        msg.add_attachment(eicar_string, maintype='application', subtype='octet-stream', filename='invoice.exe')
    
    else:
        print("Unknown type. Use clean, spam, phishing, or malware.")
        return

    try:
        print(f"Injecting a [{email_type.upper()}] email into the EPG Gateway on port 25...")
        with smtplib.SMTP('127.0.0.1', 25) as server:
            server.send_message(msg)
        print("Successfully injected! Check your EPG Orchestrator logs or Dashboard.")
    except Exception as e:
        print(f"Failed to inject email: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        send_test_email(sys.argv[1].lower())
    else:
        print("Usage: python generate_and_send.py [clean|spam|phishing|malware]")
