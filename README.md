# Threat-Detection-Engineering-Case-Study-One

## Overview and Objectives

This project aims to simulate the process of detection rule tuning and testing, through the use of controlled emulations of common threat actor patterns, and utilizing the results to identify lacking areas of the existing threat detection and improve rulesets.

### Goals:

- Simulate T1204.002 (User Execution - Malicious File) and T1027.010 (Obfuscated Files or Information - Command Obfuscation). 
- Verify the effectiveness of default threat detection coverage against those techniques in a Wazuh environment.
- Write custom Wazuh rules to mitigates the gaps identified.
- Create a Github Actions DaC pipeline to automatically validate new rules using historical log data.

### Lab Architecture

- An Ubuntu Server v26.04 EC2 instance hosting the Wazuh Manager, Indexer and Dashboard.
- A Windows 11 Enterprise EC2 instance hosting the Wazuh Agent, as well as Sysmon, using the [SwiftOnSecurity community Sysmon configuration](https://github.com/SwiftOnSecurity/sysmon-config).
- Github Actions Runner (N\A).

## Scenario 1: Powershell Obfuscation & Rule Tuning (T1027.010)

This scenario uses a PowerShell script, Invoke-EncodedPowerShellTest.ps1, to spawn another PowerShell process that executes a base64 encoded command.

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "Test start: $(Get-Date -Format o)"
Write-Host 'WAZUH-PLAIN-TEST: this harness process is the negative baseline.'

$command = 'Write-Output "WAZUH-ENCODED-TEST"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

Write-Host "Encoded payload: $encodedCommand"
powershell.exe -EncodedCommand $encodedCommand
```

Executing the script revealed two key details:
- The default rules caught the execution of the encoded command, and
- It did not catch the execution of the base script.

The reason for the first can be attributed to Rule 92057 in /var/ossec/ruleset/rules/0800-sysmon_id_1.xml.
```xml
<rule id="92057" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)powershell\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)powershell\.exe.+\-\b(encodedcommand|e|ea|ec|encodeda|encode|en|enco)\b</field>
  <options>no_full_log</options>
  <description>Powershell.exe spawned a powershell process which executed a base64 encoded command</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

However, no detection rules exist for PowerShell scripts run by user accounts. To fix this there are two options; setting up the native PowerShell logging on Windows, but this would require extensive tuning to ensure only relevant information is collected, and leveraging the Sysmon configurations that already exist.

The former isn't necessary for a lab of such a small scope, therefore adding a new rule targeting Sysmon Event ID 1 filtered to select only normal user accounts is the way to go.
