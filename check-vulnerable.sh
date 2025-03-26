#!/bin/bash
# Check packages for vulnerabilities, includes transitive packages

VULN_JSON_PATH="/tmp/trivy_report.json"
VULN_TABLE_PATH="/tmp/trivy_report_table.txt"
SOURCE_PATH="Source/"

dotnet restore "$SOURCE_PATH"

trivy fs --scanners vuln --quiet --format json --skip-files "**/*.deps.json" --exit-code 1 --output "$VULN_JSON_PATH" "$SOURCE_PATH"

if [ $? -eq 1 ]; then
    echo -e "\nVulnerable packages detected, pull request is blocked form merging!" >&2
    trivy fs --scanners vuln --quiet --format table --skip-files "**/*.deps.json" "$SOURCE_PATH" | tee "$VULN_TABLE_PATH"
    echo "### Vulnerable Packages Report" >> $GITHUB_STEP_SUMMARY
    cat "$VULN_TABLE_PATH" >> $GITHUB_STEP_SUMMARY
    exit 1;
else
    echo "No vulnerable packages detected." >&1
    exit 0;
fi