---
title: AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
summary: Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)
sigma_id: 074e0ded-6ced-4ebd-8b4d-53f55908119d
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1216
author: Julia Fomina, oscd.community
date: '2020-10-06'
modified: '2022-10-09'
falsepositives:
  - Unlikely
references:
  - https://posts.specterops.io/application-whitelisting-bypass-and-arbitrary-unsigned-code-execution-technique-in-winrm-vbs-c8c24fb40404
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_winrm_awl_bypass.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
id: 074e0ded-6ced-4ebd-8b4d-53f55908119d
status: test
description: Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)
references:
    - https://posts.specterops.io/application-whitelisting-bypass-and-arbitrary-unsigned-code-execution-technique-in-winrm-vbs-c8c24fb40404
author: Julia Fomina, oscd.community
date: 2020-10-06
modified: 2022-10-09
tags:
    - attack.stealth
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    contains_format_pretty_arg:
        CommandLine|contains:
            - 'format:pretty'
            - 'format:"pretty"'
            - 'format:"text"'
            - 'format:text'
    image_from_system_folder:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    contains_winrm:
        CommandLine|contains: 'winrm'
    condition: contains_winrm and (contains_format_pretty_arg and not image_from_system_folder)
falsepositives:
    - Unlikely
level: medium
```
