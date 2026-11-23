---
title: Non Interactive PowerShell Process Spawned
summary: Detects non-interactive PowerShell activity by looking at the "powershell" process with a non-user GUI process such as "explorer.exe" as a parent.
sigma_id: f4bbd493-b796-416e-bbf2-121235348529
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
author: Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements)
date: '2019-09-12'
modified: '2026-11-05'
falsepositives:
  - Likely. Many admin scripts and tools leverage PowerShell in their BAT or VB scripts which may trigger this rule often. It is best to add additional filters or use this to hunt for anomalies
references:
  - https://web.archive.org/web/20200925032237/https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190410151110.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_non_interactive_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Non Interactive PowerShell Process Spawned
id: f4bbd493-b796-416e-bbf2-121235348529
status: test
description: Detects non-interactive PowerShell activity by looking at the "powershell" process with a non-user GUI process such as "explorer.exe" as a parent.
references:
    - https://web.archive.org/web/20200925032237/https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190410151110.html
author: Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements)
date: 2019-09-12
modified: 2026-11-05
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
    filter_main_generic:
        ParentImage|endswith:
            - ':\Windows\explorer.exe'
            - ':\Windows\System32\CompatTelRunner.exe'
            - ':\Windows\SysWOW64\explorer.exe'
    filter_main_windows_update:
        ParentImage|endswith: ':\$WINDOWS.~BT\Sources\SetupHost.exe' # During Windows updates/upgrades
        # CommandLine: powershell.exe -ExecutionPolicy Restricted -Command Write-Host 'Final result: 1';
    filter_optional_vscode:
        # Triggered by VsCode when you open a Shell inside the workspace
        ParentImage|endswith: '\AppData\Local\Programs\Microsoft VS Code\Code.exe'
        ParentCommandLine|contains: ' --ms-enable-electron-run-as-node '
    filter_optional_terminal:
        ParentImage|contains: ':\Program Files\WindowsApps\Microsoft.WindowsTerminal_'
        ParentImage|endswith: '\WindowsTerminal.exe'
    filter_optional_defender:
        ParentImage|endswith: ':\Program Files\Windows Defender Advanced Threat Protection\SenseIR.exe'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Likely. Many admin scripts and tools leverage PowerShell in their BAT or VB scripts which may trigger this rule often. It is best to add additional filters or use this to hunt for anomalies
level: low
```
