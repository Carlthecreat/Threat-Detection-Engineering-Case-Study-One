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
- A Windows 11 Enterprise EC2 instance hosting the Wazuh Agent, as well as Sysmon, using the SwiftOnSecurity community configuration.
- Github Actions Runner (N\A).

## Scenario 1: Powershell Obfuscation & Rule Tuning (
