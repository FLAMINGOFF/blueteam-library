---
title: PUA - Restic Backup Tool Execution
summary: |-
  Detects the execution of the Restic backup tool, which can be used for data exfiltration.
  Threat actors may leverage Restic to back up and exfiltrate sensitive data to remote storage locations, including cloud services.
  If not legitimately used in the enterprise environment, its presence may indicate malicious activity.
sigma_id: 6ddff2e8-ea1a-45d0-8938-93dfc1d67ae7
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0010
techniques:
  - T1048
  - T1567.002
author: Nounou Mbeiri, Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2025-10-17'
falsepositives:
  - Legitimate use of Restic for backup purposes within the organization.
references:
  - https://thedfirreport.com/2024/09/30/nitrogen-campaign-drops-sliver-and-ends-with-blackcat-ransomware/#exfiltration
  - https://restic.net/
  - https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_restic.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - Restic Backup Tool Execution
id: 6ddff2e8-ea1a-45d0-8938-93dfc1d67ae7
status: experimental
description: |
    Detects the execution of the Restic backup tool, which can be used for data exfiltration.
    Threat actors may leverage Restic to back up and exfiltrate sensitive data to remote storage locations, including cloud services.
    If not legitimately used in the enterprise environment, its presence may indicate malicious activity.
references:
    - https://thedfirreport.com/2024/09/30/nitrogen-campaign-drops-sliver-and-ends-with-blackcat-ransomware/#exfiltration
    - https://restic.net/
    - https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html
author: Nounou Mbeiri, Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-10-17
tags:
    - attack.exfiltration
    - attack.t1048
    - attack.t1567.002
logsource:
    product: windows
    category: process_creation
detection:
    selection_specific:
        - CommandLine|contains|all:
              - '--password-file'
              - 'init'
              - ' -r '
        - CommandLine|contains|all:
              - '--use-fs-snapshot'
              - 'backup'
              - ' -r '
    selection_restic:
        CommandLine|contains:
            - 'sftp:'
            - 'rest:http'
            - 's3:s3.'
            - 's3.http'
            - 'azure:'
            - ' gs:'
            - 'rclone:'
            - 'swift:'
            - ' b2:'
        CommandLine|contains|all:
            - ' init '
            - ' -r '
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Restic for backup purposes within the organization.
level: high
```
