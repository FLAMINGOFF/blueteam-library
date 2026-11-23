---
title: Suspicious NTLM Authentication on the Printer Spooler Service
summary: Detects a privilege elevation attempt by coercing NTLM authentication on the Printer Spooler service
sigma_id: bb76d96b-821c-47cf-944b-7ce377864492
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0006
techniques:
  - T1212
author: Elastic (idea), Tobias Michalski (Nextron Systems)
date: '2022-05-04'
modified: '2023-02-09'
falsepositives:
  - Unknown
references:
  - https://twitter.com/med0x2e/status/1520402518685200384
  - https://github.com/elastic/detection-rules/blob/dd224fb3f81d0b4bf8593c5f02a029d647ba2b2d/rules/windows/credential_access_relay_ntlm_auth_via_http_spoolss.toml
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_ntlmrelay.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious NTLM Authentication on the Printer Spooler Service
id: bb76d96b-821c-47cf-944b-7ce377864492
status: test
description: Detects a privilege elevation attempt by coercing NTLM authentication on the Printer Spooler service
references:
    - https://twitter.com/med0x2e/status/1520402518685200384
    - https://github.com/elastic/detection-rules/blob/dd224fb3f81d0b4bf8593c5f02a029d647ba2b2d/rules/windows/credential_access_relay_ntlm_auth_via_http_spoolss.toml
author: Elastic (idea), Tobias Michalski (Nextron Systems)
date: 2022-05-04
modified: 2023-02-09
tags:
    - attack.privilege-escalation
    - attack.credential-access
    - attack.t1212
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'C:\windows\system32\davclnt.dll,DavSetCookie'
            - 'http'
        CommandLine|contains:
            - 'spoolss'
            - 'srvsvc'
            - '/print/pipe/'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
