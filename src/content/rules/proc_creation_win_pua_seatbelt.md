---
title: PUA - Seatbelt Execution
summary: Detects the execution of the PUA/Recon tool Seatbelt via PE information of command line parameters
sigma_id: 38646daa-e78f-4ace-9de0-55547b2d30da
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1526
  - T1087
  - T1083
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-10-18'
modified: '2023-02-04'
falsepositives:
  - Unlikely
references:
  - https://github.com/GhostPack/Seatbelt
  - https://web.archive.org/web/20250718134453/https://www.bluetangle.dev/2022/08/fastening-seatbelt-on-threat-hunting.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_seatbelt.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - Seatbelt Execution
id: 38646daa-e78f-4ace-9de0-55547b2d30da
status: test
description: Detects the execution of the PUA/Recon tool Seatbelt via PE information of command line parameters
references:
    - https://github.com/GhostPack/Seatbelt
    - https://web.archive.org/web/20250718134453/https://www.bluetangle.dev/2022/08/fastening-seatbelt-on-threat-hunting.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-18
modified: 2023-02-04
tags:
    - attack.discovery
    - attack.t1526
    - attack.t1087
    - attack.t1083
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\Seatbelt.exe'
        - OriginalFileName: 'Seatbelt.exe'
        - Description: 'Seatbelt'
        - CommandLine|contains:
              # This just a list of the commands that will produce the least amount of FP in "theory"
              # Comment out/in as needed in your environment
              # To get the full list of commands see reference section
              - ' DpapiMasterKeys'
              - ' InterestingProcesses'
              - ' InterestingFiles'
              - ' CertificateThumbprints'
              - ' ChromiumBookmarks'
              - ' ChromiumHistory'
              - ' ChromiumPresence'
              - ' CloudCredentials'
              - ' CredEnum'
              - ' CredGuard'
              - ' FirefoxHistory'
              - ' ProcessCreationEvents'
              # - ' RDPSessions'
              # - ' PowerShellHistory'
    selection_group_list:
        CommandLine|contains:
            - ' -group=misc'
            - ' -group=remote'
            - ' -group=chromium'
            - ' -group=slack'
            - ' -group=system'
            - ' -group=user'
            - ' -group=all'
    selection_group_output:
        CommandLine|contains: ' -outputfile='
    condition: selection_img or all of selection_group_*
falsepositives:
    - Unlikely
level: high
```
