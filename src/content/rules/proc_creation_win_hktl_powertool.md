---
title: HackTool - PowerTool Execution
summary: Detects the execution of the tool PowerTool which has the ability to kill a process, delete its process file, unload drivers, and delete the driver files
sigma_id: a34f79a3-8e5f-4cc3-b765-de00695452c2
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-11-29'
modified: '2023-02-04'
falsepositives:
  - Unlikely
references:
  - https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/
  - https://www.trendmicro.com/en_us/research/22/i/play-ransomware-s-attack-playbook-unmasks-it-as-another-hive-aff.html
  - https://twitter.com/gbti_sa/status/1249653895900602375?lang=en
  - https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_powertool.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - PowerTool Execution
id: a34f79a3-8e5f-4cc3-b765-de00695452c2
status: test
description: Detects the execution of the tool PowerTool which has the ability to kill a process, delete its process file, unload drivers, and delete the driver files
references:
    - https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/
    - https://www.trendmicro.com/en_us/research/22/i/play-ransomware-s-attack-playbook-unmasks-it-as-another-hive-aff.html
    - https://twitter.com/gbti_sa/status/1249653895900602375?lang=en
    - https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-11-29
modified: 2023-02-04
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        - Image|endswith:
              - '\PowerTool.exe'
              - '\PowerTool64.exe'
        - OriginalFileName: 'PowerTool.exe'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
