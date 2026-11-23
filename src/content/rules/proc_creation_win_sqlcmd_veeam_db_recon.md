---
title: Veeam Backup Database Suspicious Query
summary: Detects potentially suspicious SQL queries using SQLCmd targeting the Veeam backup databases in order to steal information.
sigma_id: 696bfb54-227e-4602-ac5b-30d9d2053312
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1005
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-05-04'
falsepositives:
  - Unknown
references:
  - https://labs.withsecure.com/publications/fin7-target-veeam-servers
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sqlcmd_veeam_db_recon.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Veeam Backup Database Suspicious Query
id: 696bfb54-227e-4602-ac5b-30d9d2053312
status: test
description: Detects potentially suspicious SQL queries using SQLCmd targeting the Veeam backup databases in order to steal information.
references:
    - https://labs.withsecure.com/publications/fin7-target-veeam-servers
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-04
tags:
    - attack.collection
    - attack.t1005
logsource:
    category: process_creation
    product: windows
detection:
    selection_sql:
        Image|endswith: '\sqlcmd.exe'
        CommandLine|contains|all:
            - 'VeeamBackup'
            - 'From '
    selection_db:
        CommandLine|contains:
            - 'BackupRepositories'
            - 'Backups'
            - 'Credentials'
            - 'HostCreds'
            - 'SmbFileShares'
            - 'Ssh_creds'
            - 'VSphereInfo'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
