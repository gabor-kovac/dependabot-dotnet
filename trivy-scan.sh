#!/bin/bash
# Check package vulnerabilities and license using Trivy
# Outputs markdown tables to github step summary

# Variables

if [ -z "$TRIVY_SCAN_PATH" ]; then
    SCAN_PATH="Source/"
else
    SCAN_PATH="$TRIVY_SCAN_PATH"
fi

if [ -z "$TRVIY_SKIP_FILES" ]; then
    SKIP_FILES="**/*.deps.json"
else
    SKIP_FILES="$TRVIY_SKIP_FILES"
fi

if [ -z "$TRIVY_SEVERITY" ]; then
    LICENSE_SEVERITY="UNKNOWN,HIGH,CRITICAL,LOW"
else
    LICENSE_SEVERITY="$TRIVY_SEVERITY"
fi

TRIVY_VULN_REPORT_PATH="/tmp/trivy_vuln_report.json"
TRIVY_LICENSE_REPORT_PATH="/tmp/trivy_license_report.json"

VULN_TABLE_PATH="/tmp/trivy_vuln_report_table.md"
LICENSE_TABLE_PATH="/tmp/trivy_license_report_table.md"

VULN_SCAN_RESULT=0
LICENSE_SCAN_RESULT=0
EXIT_CODE=0

# Script begin

rm -f "$TRIVY_VULN_REPORT_PATH" "$TRIVY_LICENSE_REPORT_PATH" "$VULN_TABLE_PATH" "$LICENSE_TABLE_PATH"

if [ -z "$TRIVY_RESTORE_DISABLE" ] || [ "$TRIVY_RESTORE_DISABLE" -eq 0 ]; then
    dotnet restore "$SCAN_PATH" --use-lock-file
fi

trivy fs --scanners vuln --quiet --format json --skip-files "$SKIP_FILES" --exit-code 1 --output "$TRIVY_VULN_REPORT_PATH" "$SCAN_PATH"
VULN_SCAN_RESULT=$?

trivy fs --scanners license --severity "$LICENSE_SEVERITY" --quiet --format json --skip-files "$SKIP_FILES" --exit-code 1 --output "$TRIVY_LICENSE_REPORT_PATH" "$SCAN_PATH"
LICENSE_SCAN_RESULT=$?

if [ "$VULN_SCAN_RESULT" -eq 1 ]; then
    EXIT_CODE=1
    jq -c '.Results[] | select(.Class == "lang-pkgs") | .Target as $TARGET | .Type as $TYPE | select(has("Vulnerabilities")) | .Vulnerabilities[] | {Package: .PkgName, Installed: .InstalledVersion, "Fixed version": .FixedVersion, ID: .VulnerabilityID, Severity: .Severity, Title: .Title, Target: $TARGET, Type: $TYPE}' "$TRIVY_VULN_REPORT_PATH" | jtbl --markdown > "$VULN_TABLE_PATH"
    echo "Vulnerable packages have been found!" >&2
    echo "### Vulnerable packages have been found" >> $GITHUB_STEP_SUMMARY
    cat "$VULN_TABLE_PATH" >> $GITHUB_STEP_SUMMARY
    echo "VULNERABLE_PACKAGES_FOUND=true" >> $GITHUB_OUTPUT
fi

if [ "$LICENSE_SCAN_RESULT" -eq 1 ]; then
    EXIT_CODE=1
    jq -c '.Results[] | select(.Class == "license") | select(has("Licenses")) | .Licenses[] | {Package: .PkgName, License: .Name, Category: .Category, Severity: .Severity, Path: .FilePath}' "$TRIVY_LICENSE_REPORT_PATH" | jtbl --markdown > "$LICENSE_TABLE_PATH"
    echo "License issues have been found!" >&2
    echo "### License issues have been found" >> $GITHUB_STEP_SUMMARY
    cat "$LICENSE_TABLE_PATH" >> $GITHUB_STEP_SUMMARY
    echo "LICENSE_ERROR_FOUND=true" >> $GITHUB_OUTPUT
fi

if [ "$EXIT_CODE" -eq 1 ]; then
    echo "QUALITY_GATE_FAILED=true" >> $GITHUB_OUTPUT
    exit 1;
else
    echo "No vulnerable packages detected, licenses are in check." >&1
    echo "QUALITY_GATE_FAILED=false" >> $GITHUB_OUTPUT
    echo "LICENSE_ERROR_FOUND=false" >> $GITHUB_OUTPUT
    echo "VULNERABLE_PACKAGES_FOUND=false" >> $GITHUB_OUTPUT
    exit 0;
fi
