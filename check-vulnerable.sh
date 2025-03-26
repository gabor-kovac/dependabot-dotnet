#!/bin/bash
# Check dotnet packages for vulnerabilities, includes transitive packages

dotnet restore

dotnet list package --vulnerable --include-transitive --format json > /tmp/vulnerable_packages.json

if jq -e '.. | objects | select(has("vulnerabilities"))' /tmp/vulnerable_packages.json > /dev/null 2>&1; then
    echo "Vulnerable packages detected:" >&2
    jq '.. | objects | select(has("vulnerabilities")) | .vulnerabilities' /tmp/vulnerable_packages.json >&2
    exit 1
else
    echo "No vulnerable packages detected." >&1
    exit 0
fi
