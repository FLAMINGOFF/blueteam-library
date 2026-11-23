---
title: Mshtml.DLL RunHTMLApplication Suspicious Usage
summary: Detects execution of commands that leverage the "mshtml.dll" RunHTMLApplication export to run arbitrary code via different protocol handlers (vbscript, javascript, file, http...)
sigma_id: 4782eb5a-a513-4523-a0ac-f3082b26ac5c
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems),  Florian Roth (Nextron Systems), Josh Nickels, frack113, Zaw Min Htun (ZETA)
date: '2022-08-14'
modified: '2024-02-23'
falsepositives:
  - Unlikely
references:
  - https://twitter.com/n1nj4sec/status/1421190238081277959
  - https://hyp3rlinx.altervista.org/advisories/MICROSOFT_WINDOWS_DEFENDER_TROJAN.WIN32.POWESSERE.G_MITIGATION_BYPASS_PART2.txt
  - http://hyp3rlinx.altervista.org/advisories/MICROSOFT_WINDOWS_DEFENDER_DETECTION_BYPASS.txt
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_mshtml_runhtmlapplication.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Mshtml.DLL RunHTMLApplication Suspicious Usage
id: 4782eb5a-a513-4523-a0ac-f3082b26ac5c
related:
    - id: 9f06447a-a33a-4cbe-a94f-a3f43184a7a3
      type: obsolete
    - id: 73fcad2e-ff14-4c38-b11d-4172c8ac86c7
      type: obsolete
status: test
description: |
    Detects execution of commands that leverage the "mshtml.dll" RunHTMLApplication export to run arbitrary code via different protocol handlers (vbscript, javascript, file, http...)
references:
    - https://twitter.com/n1nj4sec/status/1421190238081277959
    - https://hyp3rlinx.altervista.org/advisories/MICROSOFT_WINDOWS_DEFENDER_TROJAN.WIN32.POWESSERE.G_MITIGATION_BYPASS_PART2.txt
    - http://hyp3rlinx.altervista.org/advisories/MICROSOFT_WINDOWS_DEFENDER_DETECTION_BYPASS.txt
author: Nasreddine Bencherchali (Nextron Systems),  Florian Roth (Nextron Systems), Josh Nickels, frack113, Zaw Min Htun (ZETA)
date: 2022-08-14
modified: 2024-02-23
tags:
    - attack.execution
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\..\'
            - 'mshtml'
        CommandLine|contains:
            - '#135'
            - 'RunHTMLApplication'
    condition: selection
falsepositives:
    - Unlikely
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_rundll32_mshtml_runhtmlapplication/info.yml
```
