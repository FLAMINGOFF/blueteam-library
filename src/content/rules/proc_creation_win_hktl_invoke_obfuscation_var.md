---
title: Invoke-Obfuscation VAR+ Launcher
summary: Detects Obfuscated use of Environment Variables to execute PowerShell
sigma_id: 27aec9c9-dbb0-4939-8422-1742242471d0
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
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_var.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Invoke-Obfuscation VAR+ Launcher
id: 27aec9c9-dbb0-4939-8422-1742242471d0
status: test
description: Detects Obfuscated use of Environment Variables to execute PowerShell
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task 24)
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
        # Example 1: C:\winDoWs\SySTeM32\cmd.Exe /C"SET NOtI=Invoke-Expression (New-Object Net.WebClient).DownloadString&& PowERshElL -NOl SET-iteM ( 'VAR' + 'i'+ 'A' + 'blE:Ao6' + 'I0') ( [TYpe](\"{2}{3}{0}{1}\"-F 'iRoN','mENT','e','nv') ) ; ${exECUtIONCOnTEXT}.\"IN`VO`KecOmMaND\".\"inVo`KES`crIPt\"( ( ( GEt-VAriAble ( 'a' + 'o6I0') -vaLU )::(\"{1}{4}{2}{3}{0}\" -f'e','gETenvIR','NtvaRIa','BL','ONme' ).Invoke(( \"{0}{1}\"-f'n','oti' ),( \"{0}{1}\" -f'pRoC','esS') )) )"
        # Example 2: cMD.exe /C "seT SlDb=Invoke-Expression (New-Object Net.WebClient).DownloadString&& pOWErShell .(( ^&(\"{1}{0}{2}{3}\" -f 'eT-vaR','G','iab','lE' ) (\"{0}{1}\" -f '*m','DR*' ) ).\"na`ME\"[3,11,2]-JOIN'' ) ( ( ^&(\"{0}{1}\" -f'g','CI' ) (\"{0}{1}\" -f 'ENV',':SlDb' ) ).\"VA`luE\" ) "
        CommandLine|re: 'cmd.{0,5}(?:/c|/r)(?:\s|)\"set\s[a-zA-Z]{3,6}.*(?:\{\d\}){1,}\\\"\s+?\-f(?:.*\)){1,}.*\"'
    condition: selection
falsepositives:
    - Unknown
level: high
```
