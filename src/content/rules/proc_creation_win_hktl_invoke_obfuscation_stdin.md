---
title: Invoke-Obfuscation STDIN+ Launcher
summary: Detects Obfuscated use of stdin to execute PowerShell
sigma_id: 6c96fc76-0eb1-11eb-adc1-0242ac120002
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1027
  - T1059.001
author: Jonathan Cheong, oscd.community
date: '2020-10-15'
modified: '2024-04-15'
falsepositives:
  - Unknown
references:
  - https://github.com/SigmaHQ/sigma/issues/1009
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_stdin.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Invoke-Obfuscation STDIN+ Launcher
id: 6c96fc76-0eb1-11eb-adc1-0242ac120002
status: test
description: Detects Obfuscated use of stdin to execute PowerShell
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task 25)
author: Jonathan Cheong, oscd.community
date: 2020-10-15
modified: 2024-04-15
tags:
    - attack.stealth
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Example 1: c:\windows\sYstEm32\CmD.eXE /C"echO\Invoke-Expression (New-Object Net.WebClient).DownloadString | POwersHELl -NoEXiT -"
        # Example 2: c:\WiNDOws\sysTEm32\cmd.EXe /C " ECHo Invoke-Expression (New-Object Net.WebClient).DownloadString | POwersHELl -nol ${EXEcUtIONCONTeXT}.INvOkEComMANd.InvOKEScRIPt( $InpUt )"
        CommandLine|re: 'cmd.{0,5}(?:/c|/r).+powershell.+(?:\$\{?input\}?|noexit).+\"'
    condition: selection
falsepositives:
    - Unknown
level: high
```
