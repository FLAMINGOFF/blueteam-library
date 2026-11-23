---
title: Renamed PingCastle Binary Execution
summary: Detects the execution of a renamed "PingCastle" binary based on the PE metadata fields.
sigma_id: 2433a154-bb3d-42e4-86c3-a26bdac91c45
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
  - T1202
author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
date: '2024-01-11'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
  - https://www.pingcastle.com/documentation/scanner/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_pingcastle.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed PingCastle Binary Execution
id: 2433a154-bb3d-42e4-86c3-a26bdac91c45
status: test
description: Detects the execution of a renamed "PingCastle" binary based on the PE metadata fields.
references:
    - https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
    - https://www.pingcastle.com/documentation/scanner/
author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
date: 2024-01-11
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - OriginalFileName:
              - 'PingCastleReporting.exe'
              - 'PingCastleCloud.exe'
              - 'PingCastle.exe'
        - CommandLine|contains:
              - '--scanner aclcheck'
              - '--scanner antivirus'
              - '--scanner computerversion'
              - '--scanner foreignusers'
              - '--scanner laps_bitlocker'
              - '--scanner localadmin'
              - '--scanner nullsession'
              - '--scanner nullsession-trust'
              - '--scanner oxidbindings'
              - '--scanner remote'
              - '--scanner share'
              - '--scanner smb'
              - '--scanner smb3querynetwork'
              - '--scanner spooler'
              - '--scanner startup'
              - '--scanner zerologon'
        - CommandLine|contains: '--no-enum-limit'
        - CommandLine|contains|all:
              - '--healthcheck'
              - '--level Full'
        - CommandLine|contains|all:
              - '--healthcheck'
              - '--server '
    filter_main_img:
        Image|endswith:
            - '\PingCastleReporting.exe'
            - '\PingCastleCloud.exe'
            - '\PingCastle.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
