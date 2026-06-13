================================================================================
EGP Project - Azure Deployment Package
================================================================================
Created: May 4, 2026
Source: D:\ZZZZZZZZZZZZ (excluding EPG_Final.zip)

================================================================================
WHAT'S INCLUDED
================================================================================

1. docker-compose.yml
   - Main Docker Compose configuration

2. EPG/ (110 MB - cleaned)
   - All source code and configurations
   - EXCLUDED: .venv (Python virtual env - recreate with pip install -r requirements.txt)
   - EXCLUDED: __pycache__ (Python bytecode - auto-generated)
   - EXCLUDED: tests/ (test files - not needed for production)
   - EXCLUDED: *.pyc (compiled Python files)

3. dashboard/ 
   - Dashboard API and static files

4. local_mail_client/
   - Mail client code

5. mailu/
   - epg-bridge/ (custom bridge code)
   - data/domains/ (email data - excludes locked Dovecot index files)
   - data/ssl/ (SSL certificates structure)
   - data/var/ (Rspamd configuration)
   
   EXCLUDED from mailu:
   - data/log/ (log files - regenerated at runtime)
   - data/queue/ (mail queue - runtime data)
   - data/redis/ (Redis dump - runtime cache)
   - data/roundcube/logs/ (webmail logs)
   - data/roundcube/enigma/ (encryption keys - regenerate)
   - Dovecot index files (locked/regenerated)

================================================================================
WHAT TO DO BEFORE AZURE UPLOAD
================================================================================

1. If you need email data:
   - Stop the Mailu containers first
   - Then copy D:\ZZZZZZZZZZZZ\mailu\data\domains manually
   
2. If you need Redis data:
   - Copy mailu/data/redis/dump.rdb separately if needed

3. SSL Certificates:
   - If using Let's Encrypt, they'll be regenerated
   - If using custom certs, copy them to mailu/data/ssl/

4. Python Virtual Environment:
   - After deployment, run: pip install -r requirements.txt
   - For EPG: cd EPG && pip install -r requirements.txt
   - For each service with its own requirements.txt

================================================================================
RECOMMENDED AZURE IGNORE FILE
================================================================================
Create a .azureignore or .dockerignore with:

# Python
**/.venv/
**/__pycache__/
**/*.pyc
**/*.pyo
**/.pytest_cache/

# IDE
**/.idea/
**/.vscode/
**/*.iml

# Logs
**/logs/
**/*.log

# Runtime data
mailu/data/log/
mailu/data/queue/
mailu/data/redis/
mailu/data/roundcube/logs/

# Test files
**/tests/

# OS files
.DS_Store
Thumbs.db

================================================================================
SIZE COMPARISON
================================================================================
Original (without EPG_Final.zip): ~700 MB
This package:                      ~110 MB
Saved:                             ~590 MB (84% reduction)

================================================================================
