---
title: Linux Logs Clearing Attempts
summary: |-
  Detects logs clearing attempts on Linux systems via utilities such as 'rm', 'rmdir', 'shred', and 'unlink' targeting log files and directories.
  Adversaries often try to clear logs to cover their tracks after performing malicious activities.
sigma_id: 80915f59-9b56-4616-9de0-fd0dea6c12fe
status: stable
level: medium
platform: linux
logsource: linux / process_creation
tactics: []
techniques:
  - T1685.006
author: Ömer Günal, oscd.community
date: '2020-10-07'
modified: '2026-03-18'
falsepositives:
  - Legitimate administration activities
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.002/T1070.002.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_clear_logs.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Linux Logs Clearing Attempts
id: 80915f59-9b56-4616-9de0-fd0dea6c12fe
status: stable
description: |
    Detects logs clearing attempts on Linux systems via utilities such as 'rm', 'rmdir', 'shred', and 'unlink' targeting log files and directories.
    Adversaries often try to clear logs to cover their tracks after performing malicious activities.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.002/T1070.002.md
author: Ömer Günal, oscd.community
date: 2020-10-07
modified: 2026-03-18
tags:
    - attack.defense-impairment
    - attack.t1685.006
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/rm'    # covers /rmdir as well
            - '/rmdir'
            - '/shred'
            - '/unlink'
        CommandLine|contains:
            - '/var/log'
            - '/var/spool/mail'
    filter_main_legit_systat:
        Image|endswith: '/rm'
        CommandLine|startswith: 'rm -f /var/log/sysstat/'
    filter_main_dmseg:
        Image|endswith: '/rm'
        CommandLine|startswith: 'rm -f -- /var/log//dmesg' # // before dmesg is not typo
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate administration activities
level: medium
```
