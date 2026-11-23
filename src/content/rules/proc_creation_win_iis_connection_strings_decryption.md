---
title: Microsoft IIS Connection Strings Decryption
summary: >-
  Detects use of aspnet_regiis to decrypt Microsoft IIS connection strings. An attacker with Microsoft IIS web server access via a webshell or alike can decrypt and dump any hardcoded connection
  strings, such as the MSSQL service account password using aspnet_regiis command.
sigma_id: 97dbf6e2-e436-44d8-abee-4261b24d3e41
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003
author: Tim Rauch, Elastic (idea)
date: '2022-09-28'
modified: '2022-12-30'
falsepositives:
  - Unknown
references:
  - https://www.elastic.co/guide/en/security/current/microsoft-iis-connection-strings-decryption.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_iis_connection_strings_decryption.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Microsoft IIS Connection Strings Decryption
id: 97dbf6e2-e436-44d8-abee-4261b24d3e41
status: test
description: Detects use of aspnet_regiis to decrypt Microsoft IIS connection strings. An attacker with Microsoft IIS web server access via a webshell or alike can decrypt and dump any hardcoded connection strings, such as the MSSQL service account password using aspnet_regiis command.
references:
    - https://www.elastic.co/guide/en/security/current/microsoft-iis-connection-strings-decryption.html
author: Tim Rauch, Elastic (idea)
date: 2022-09-28
modified: 2022-12-30
tags:
    - attack.credential-access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection_name:
        - Image|endswith: '\aspnet_regiis.exe'
        - OriginalFileName: 'aspnet_regiis.exe'
    selection_args:
        CommandLine|contains|all:
            - 'connectionStrings'
            - ' -pdf'
    condition: all of selection*
falsepositives:
    - Unknown
level: high
```
