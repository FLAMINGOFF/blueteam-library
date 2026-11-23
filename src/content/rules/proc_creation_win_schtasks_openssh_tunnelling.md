---
title: Potential SSH Tunnel Persistence Install Using A Scheduled Task
summary: >-
  Detects the creation of new scheduled tasks via commandline, using Schtasks.exe. This rule detects tasks creating that call OpenSSH, which may indicate the creation of reverse SSH tunnel to the
  attacker's server.
sigma_id: 2daa93a0-a5fb-41c5-8cd8-3c11294bfd1f
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
  - TA0011
techniques:
  - T1053.005
author: Rory Duncan
date: '2025-07-14'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
  - https://www.kroll.com/en/insights/publications/cyber/cactus-ransomware-prickly-new-variant-evades-detection
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_openssh_tunnelling.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential SSH Tunnel Persistence Install Using A Scheduled Task
id: 2daa93a0-a5fb-41c5-8cd8-3c11294bfd1f
status: experimental
description: Detects the creation of new scheduled tasks via commandline, using Schtasks.exe. This rule detects tasks creating that call OpenSSH, which may indicate the creation of reverse SSH tunnel to the attacker's server.
references:
    - https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
    - https://www.kroll.com/en/insights/publications/cyber/cactus-ransomware-prickly-new-variant-evades-detection
author: Rory Duncan
date: 2025-07-14
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.t1053.005
    - attack.command-and-control
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_cli_sshd:
        CommandLine|contains|all:
            - ' /create '
            - 'sshd.exe'
            - '-f'
    selection_cli_ssh:
        CommandLine|contains|all:
            - ' /create '
            - 'ssh.exe'
            - '-i'
    condition: selection_img and 1 of selection_cli_*
falsepositives:
    - Unknown
level: high
```
