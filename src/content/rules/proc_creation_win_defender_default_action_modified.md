---
title: PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction'
summary: |-
  Detects the use of PowerShell to execute the 'Set-MpPreference' cmdlet to configure Windows Defender's threat severity default action to 'Allow' (value '6') or 'NoAction' (value '9').
  This is a highly suspicious configuration change that effectively disables Defender's ability to automatically mitigate threats of a certain severity level.
  An attacker might use this technique via the command line to bypass defenses before executing payloads.
sigma_id: 1e8a9b4d-3c2a-4f9b-8d1e-7c6a5b4f3d2e
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
author: Matt Anderson (Huntress)
date: '2025-07-11'
falsepositives:
  - Highly unlikely
references:
  - https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference
  - https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/security-malware-windows-defender-threatseveritydefaultaction
  - https://research.splunk.com/endpoint/7215831c-8252-4ae3-8d43-db588e82f952
  - https://gist.github.com/Dump-GUY/8daef859f382b895ac6fd0cf094555d2
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_defender_default_action_modified.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction'
id: 1e8a9b4d-3c2a-4f9b-8d1e-7c6a5b4f3d2e
related:
    - id: 5a9e1b2c-8f7d-4a1e-9b3c-0f6d7e5a4b1f
      type: similar
status: experimental
description: |
    Detects the use of PowerShell to execute the 'Set-MpPreference' cmdlet to configure Windows Defender's threat severity default action to 'Allow' (value '6') or 'NoAction' (value '9').
    This is a highly suspicious configuration change that effectively disables Defender's ability to automatically mitigate threats of a certain severity level.
    An attacker might use this technique via the command line to bypass defenses before executing payloads.
references:
    - https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference
    - https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/security-malware-windows-defender-threatseveritydefaultaction
    - https://research.splunk.com/endpoint/7215831c-8252-4ae3-8d43-db588e82f952
    - https://gist.github.com/Dump-GUY/8daef859f382b895ac6fd0cf094555d2
    - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
author: 'Matt Anderson (Huntress)'
date: 2025-07-11
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmdlet:
        CommandLine|contains: 'Set-MpPreference'
    selection_action:
        CommandLine|contains:
            - '-LowThreatDefaultAction'
            - '-ModerateThreatDefaultAction'
            - '-HighThreatDefaultAction'
            - '-SevereThreatDefaultAction'
            - '-ltdefac '
            - '-mtdefac '
            - '-htdefac '
            - '-stdefac '
    selection_value:
        CommandLine|contains:
            - 'Allow'
            - '6'
            - 'NoAction'
            - '9'
    condition: all of selection_*
falsepositives:
    - Highly unlikely
level: high
```
