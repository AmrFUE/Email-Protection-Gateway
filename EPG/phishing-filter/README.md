# Phishing Filter (Member 2)
# Place your phishing detection project here.
#
# Required API:
#   POST /scan  - Accept .eml file, return {verdict: "PHISHING"/"CLEAN", score: 0-100}
#   GET /health - Return {status: "healthy"}
#
# The orchestrator sends the full .eml file to your /scan endpoint.
# Use shared/eml_parser.py to extract URLs, headers, and body text.
