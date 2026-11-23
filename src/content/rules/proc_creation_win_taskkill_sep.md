---
title: Taskkill Symantec Endpoint Protection
summary: >-
  Detects one of the possible scenarios for disabling Symantec Endpoint Protection.

  Symantec Endpoint Protection antivirus software services incorrectly implement the protected service mechanism.

  As a result, the NT AUTHORITY/SYSTEM user can execute the taskkill /im command several times ccSvcHst.exe /f, thereby killing the process belonging to the service, and thus shutting down the
  service.
sigma_id: 4a6713f6-3331-11ed-a261-0242ac120002
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
author: Ilya Krestinichev, Florian Roth (Nextron Systems)
date: '2022-09-13'
falsepositives:
  - Unknown
references:
  - https://www.exploit-db.com/exploits/37525
  - https://community.spiceworks.com/topic/2195015-batch-script-to-uninstall-symantec-endpoint-protection
  - https://community.broadcom.com/symantecenterprise/communities/community-home/digestviewer/viewthread?MessageKey=6ce94b67-74e1-4333-b16f-000b7fd874f0&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=digestviewer
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_taskkill_sep.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Taskkill Symantec Endpoint Protection
id: 4a6713f6-3331-11ed-a261-0242ac120002
status: test
description: |
    Detects one of the possible scenarios for disabling Symantec Endpoint Protection.
    Symantec Endpoint Protection antivirus software services incorrectly implement the protected service mechanism.
    As a result, the NT AUTHORITY/SYSTEM user can execute the taskkill /im command several times ccSvcHst.exe /f, thereby killing the process belonging to the service, and thus shutting down the service.
references:
    - https://www.exploit-db.com/exploits/37525
    - https://community.spiceworks.com/topic/2195015-batch-script-to-uninstall-symantec-endpoint-protection
    - https://community.broadcom.com/symantecenterprise/communities/community-home/digestviewer/viewthread?MessageKey=6ce94b67-74e1-4333-b16f-000b7fd874f0&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=digestviewer
author: Ilya Krestinichev, Florian Roth (Nextron Systems)
date: 2022-09-13
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'taskkill'
            - ' /F '
            - ' /IM '
            - 'ccSvcHst.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
