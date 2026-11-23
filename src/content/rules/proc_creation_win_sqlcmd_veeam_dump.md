---
title: VeeamBackup Database Credentials Dump Via Sqlcmd.EXE
summary: Detects dump of credentials in VeeamBackup dbo
sigma_id: b57ba453-b384-4ab9-9f40-1038086b4e53
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1005
author: frack113
date: '2021-12-20'
modified: '2023-02-13'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2021/12/13/diavol-ransomware/
  - https://forums.veeam.com/veeam-backup-replication-f2/recover-esxi-password-in-veeam-t34630.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sqlcmd_veeam_dump.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: VeeamBackup Database Credentials Dump Via Sqlcmd.EXE
id: b57ba453-b384-4ab9-9f40-1038086b4e53
status: test
description: Detects dump of credentials in VeeamBackup dbo
references:
    - https://thedfirreport.com/2021/12/13/diavol-ransomware/
    - https://forums.veeam.com/veeam-backup-replication-f2/recover-esxi-password-in-veeam-t34630.html
author: frack113
date: 2021-12-20
modified: 2023-02-13
tags:
    - attack.collection
    - attack.t1005
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith: '\sqlcmd.exe'
    selection_query:
        CommandLine|contains|all:
            - 'SELECT'
            - 'TOP'
            - '[VeeamBackup].[dbo].[Credentials]'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
