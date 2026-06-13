# Spam Filter (Member 1)
# Place your spam detection project here.
# 
# Required API:
#   POST /scan  - Accept .eml file, return {verdict: "SPAM"/"HAM", score: 0-100}
#   GET /health - Return {status: "healthy"}
#
# The orchestrator sends the full .eml file to your /scan endpoint.
# Use shared/eml_parser.py to extract headers and body text.
