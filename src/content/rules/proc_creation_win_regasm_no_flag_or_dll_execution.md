---
title: RegAsm.EXE Execution Without CommandLine Flags or Files
summary: |-
  Detects the execution of "RegAsm.exe" without a commandline flag or file, which might indicate potential process injection activity.
  Usually "RegAsm.exe" should point to a dedicated DLL file or call the help with the "/?" flag.
sigma_id: 651f87f7-12db-47f9-84c5-f27b081b94b6
status: experimental
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218.009
author: frack113
date: '2025-06-04'
falsepositives:
  - Legitimate use of Regasm by developers.
references:
  - https://www.mcafee.com/blogs/other-blogs/mcafee-labs/agent-teslas-unique-approach-vbs-and-steganography-for-delivery-and-intrusion/
  - https://www.zscaler.fr/blogs/security-research/threat-actors-exploit-cve-2017-11882-deliver-agent-tesla
  - https://learn.microsoft.com/en-us/dotnet/framework/tools/regasm-exe-assembly-registration-tool
  - https://app.any.run/tasks/ea944b89-69d8-49c8-ac1f-5c76ad300db2
  - https://www.joesandbox.com/analysis/1467354/0/html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_regasm_no_flag_or_dll_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: RegAsm.EXE Execution Without CommandLine Flags or Files
id: 651f87f7-12db-47f9-84c5-f27b081b94b6
status: experimental
description: |
    Detects the execution of "RegAsm.exe" without a commandline flag or file, which might indicate potential process injection activity.
    Usually "RegAsm.exe" should point to a dedicated DLL file or call the help with the "/?" flag.
references:
    - https://www.mcafee.com/blogs/other-blogs/mcafee-labs/agent-teslas-unique-approach-vbs-and-steganography-for-delivery-and-intrusion/
    - https://www.zscaler.fr/blogs/security-research/threat-actors-exploit-cve-2017-11882-deliver-agent-tesla
    - https://learn.microsoft.com/en-us/dotnet/framework/tools/regasm-exe-assembly-registration-tool
    - https://app.any.run/tasks/ea944b89-69d8-49c8-ac1f-5c76ad300db2
    - https://www.joesandbox.com/analysis/1467354/0/html
author: frack113
date: 2025-06-04
tags:
    - attack.stealth
    - attack.t1218.009
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\RegAsm.exe'
        - OriginalFileName: 'RegAsm.exe'
    selection_cli:
        CommandLine|endswith:
            - 'RegAsm'
            - 'RegAsm.exe'
            - 'RegAsm.exe"'
            - "RegAsm.exe'"
    condition: all of selection_*
falsepositives:
    - Legitimate use of Regasm by developers.
# Note: You can increase after an initial baseline
level: low
```
