#!/bin/bash
# Check package vulnerabilities and license using Trivy
# Outputs markdown tables to github step summary

# Variables

SCAN_PATH="Source/"
SKIP_FILES="**/*.deps.json"
LICENSE_SEVERITY="UNKNOWN,HIGH,CRITICAL,LOW"

TRIVY_VULN_REPORT_PATH="/tmp/trivy_vuln_report.json"
TRIVY_LICENSE_REPORT_PATH="/tmp/trivy_license_report.json"

VULN_TABLE_PATH="/tmp/trivy_vuln_report_table.md"
LICENSE_TABLE_PATH="/tmp/trivy_license_report_table.md"

VULN_SCAN_RESULT=0
LICENSE_SCAN_RESULT=0
EXIT_CODE=0

# Script begin

rm -f "$TRIVY_VULN_REPORT_PATH" "$TRIVY_LICENSE_REPORT_PATH" "$VULN_TABLE_PATH" "$LICENSE_TABLE_PATH"

dotnet restore "$SCAN_PATH"

trivy fs --scanners vuln --quiet --format json --skip-files "$SKIP_FILES" --exit-code 1 --output "$TRIVY_VULN_REPORT_PATH" "$SCAN_PATH"
VULN_SCAN_RESULT=$?

trivy fs --scanners license --severity "$LICENSE_SEVERITY" --quiet --format json --skip-files "$SKIP_FILES" --exit-code 1 --output "$TRIVY_LICENSE_REPORT_PATH" "$SCAN_PATH"
LICENSE_SCAN_RESULT=$?

if [ "$VULN_SCAN_RESULT" -eq 1 ]; then
    EXIT_CODE=1
    jq -c '.Results[] | select(.Class == "lang-pkgs") | .Target as $TARGET | .Type as $TYPE | .Vulnerabilities[] | {Package: .PkgName, Installed: .InstalledVersion, "Fixed version": .FixedVersion, ID: .VulnerabilityID, Severity: .Severity, Title: .Title, Target: $TARGET, Type: $TYPE}' "$TRIVY_VULN_REPORT_PATH" | jtbl --markdown > "$VULN_TABLE_PATH"
    echo "Vulnerable packages have been found!" >&2
    echo "### Vulnerable packages have been found" >> $GITHUB_STEP_SUMMARY
    cat "$VULN_TABLE_PATH" >> $GITHUB_STEP_SUMMARY
fi

if [ "$LICENSE_SCAN_RESULT" -eq 1 ]; then
    EXIT_CODE=1
    jq -c '.Results[] | select(.Class == "license") | .Licenses[] | {Package: .PkgName, License: .Name, Category: .Category, Severity: .Severity, Path: .FilePath}' "$TRIVY_LICENSE_REPORT_PATH" | jtbl --markdown > "$LICENSE_TABLE_PATH"
    echo "License issues have been found!" >&2
    echo "### License issues have been found" >> $GITHUB_STEP_SUMMARY
    cat "$LICENSE_TABLE_PATH" >> $GITHUB_STEP_SUMMARY
fi

if [ "$EXIT_CODE" -eq 1 ]; then
    exit 1;
else
    echo "No vulnerable packages detected, licenses are in check." >&1
    exit 0;
fi
