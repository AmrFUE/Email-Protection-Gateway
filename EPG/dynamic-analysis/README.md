# Dynamic Analysis (Member 4)
# Place your dynamic malware analysis project here.
#
# Required API:
#   POST /scan  - Accept suspicious file, return {verdict: "MALICIOUS"/"CLEAN", behaviors: [...]}
#   GET /health - Return {status: "healthy"}
#
# This stage only receives files that scored SUSPICIOUS (40-74) in the static malware scanner.
# Use cloud sandbox APIs (ANY.RUN, Hybrid Analysis) rather than local VMs to save RAM.
