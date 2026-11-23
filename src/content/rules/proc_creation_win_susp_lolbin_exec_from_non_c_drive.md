---
title: LOLBIN Execution From Abnormal Drive
summary: Detects LOLBINs executing from an abnormal or uncommon drive such as a mounted ISO.
sigma_id: d4ca7c59-e9e4-42d8-bf57-91a776efcb87
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques: []
author: Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Angelo Violetti - SEC Consult '@angelo_violetti', Aaron Herman
date: '2022-01-25'
modified: '2023-08-29'
falsepositives:
  - Rare false positives could occur on servers with multiple drives.
references:
  - https://thedfirreport.com/2021/12/13/diavol-ransomware/
  - https://web.archive.org/web/20230924005136/https://www.scythe.io/library/threat-emulation-qakbot
  - https://sec-consult.com/blog/detail/bumblebee-hunting-with-a-velociraptor/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_lolbin_exec_from_non_c_drive.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: LOLBIN Execution From Abnormal Drive
id: d4ca7c59-e9e4-42d8-bf57-91a776efcb87
related:
    - id: 5b80cf53-3a46-4adc-960b-05ec19348d74
      type: similar
status: test
description: Detects LOLBINs executing from an abnormal or uncommon drive such as a mounted ISO.
references:
    - https://thedfirreport.com/2021/12/13/diavol-ransomware/
    - https://web.archive.org/web/20230924005136/https://www.scythe.io/library/threat-emulation-qakbot
    - https://sec-consult.com/blog/detail/bumblebee-hunting-with-a-velociraptor/
author: Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Angelo Violetti - SEC Consult '@angelo_violetti', Aaron Herman
date: 2022-01-25
modified: 2023-08-29
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Note: add more lolbins for additional coverage
        - Image|endswith:
              - '\calc.exe'
              - '\certutil.exe'
              - '\cmstp.exe'
              - '\cscript.exe'
              - '\installutil.exe'
              - '\mshta.exe'
              - '\regsvr32.exe'
              - '\rundll32.exe'
              - '\wscript.exe'
        - OriginalFileName:
              - 'CALC.EXE'
              - 'CertUtil.exe'
              - 'CMSTP.EXE'
              - 'cscript.exe'
              - 'installutil.exe'
              - 'MSHTA.EXE'
              - 'REGSVR32.EXE'
              - 'RUNDLL32.EXE'
              - 'wscript.exe'
    filter_main_currentdirectory:
        CurrentDirectory|contains: 'C:\'
    filter_main_empty:
        CurrentDirectory: ''
    filter_main_null:
        CurrentDirectory: null
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Rare false positives could occur on servers with multiple drives.
level: medium
```
