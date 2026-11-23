---
title: File Encryption Using Gpg4win
summary: Detects usage of Gpg4win to encrypt files
sigma_id: 550bbb84-ce5d-4e61-84ad-e590f0024dcd
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-08-09'
falsepositives:
  - Unknown
references:
  - https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
  - https://www.gpg4win.de/documentation.html
  - https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_gpg4win_encryption.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: File Encryption Using Gpg4win
id: 550bbb84-ce5d-4e61-84ad-e590f0024dcd
status: test
description: Detects usage of Gpg4win to encrypt files
references:
    - https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
    - https://www.gpg4win.de/documentation.html
    - https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-09
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_metadata:
        - Image|endswith:
              - '\gpg.exe'
              - '\gpg2.exe'
        - Description: 'GnuPG’s OpenPGP tool'
    selection_cli:
        CommandLine|contains|all:
            - ' -c '
            - 'passphrase'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
