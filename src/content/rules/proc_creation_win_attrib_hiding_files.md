---
title: Hiding Files with Attrib.exe
summary: Detects usage of attrib.exe to hide files from users.
sigma_id: 4281cb20-2994-4580-aa63-c8b86d019934
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1564.001
author: Sami Ruohonen
date: '2019-01-16'
modified: '2023-03-14'
falsepositives:
  - IgfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)
  - Msiexec.exe hiding desktop.ini
references:
  - https://unit42.paloaltonetworks.com/unit42-sure-ill-take-new-combojack-malware-alters-clipboards-steal-cryptocurrency/
  - https://www.uptycs.com/blog/lolbins-are-no-laughing-matter
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_attrib_hiding_files.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Hiding Files with Attrib.exe
id: 4281cb20-2994-4580-aa63-c8b86d019934
status: test
description: Detects usage of attrib.exe to hide files from users.
references:
    - https://unit42.paloaltonetworks.com/unit42-sure-ill-take-new-combojack-malware-alters-clipboards-steal-cryptocurrency/
    - https://www.uptycs.com/blog/lolbins-are-no-laughing-matter
author: Sami Ruohonen
date: 2019-01-16
modified: 2023-03-14
tags:
    - attack.stealth
    - attack.t1564.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\attrib.exe'
        - OriginalFileName: 'ATTRIB.EXE'
    selection_cli:
        CommandLine|contains: ' +h '
    filter_main_msiexec:
        CommandLine|contains: '\desktop.ini '
    filter_optional_intel:
        ParentImage|endswith: '\cmd.exe'
        CommandLine: '+R +H +S +A \\\*.cui'
        ParentCommandLine: 'C:\\WINDOWS\\system32\\\*.bat'
    condition: all of selection_* and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - IgfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)
    - Msiexec.exe hiding desktop.ini
level: medium
```
