---
title: HackTool - Sliver C2 Implant Activity Pattern
summary: Detects process activity patterns as seen being used by Sliver C2 framework implants
sigma_id: 42333b2c-b425-441c-b70e-99404a17170f
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
date: '2022-08-25'
modified: '2023-03-05'
falsepositives:
  - Unlikely
references:
  - https://github.com/BishopFox/sliver/blob/79f2d48fcdfc2bee4713b78d431ea4b27f733f30/implant/sliver/shell/shell_windows.go#L36
  - https://www.microsoft.com/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_sliver_c2_execution_pattern.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
title_zh: Sliver C2 植入程序的执行特征
summary_zh: 检测 Sliver C2 框架植入程序常见的进程活动模式。
featured: true
---

```yaml
title: HackTool - Sliver C2 Implant Activity Pattern
id: 42333b2c-b425-441c-b70e-99404a17170f
status: test
description: Detects process activity patterns as seen being used by Sliver C2 framework implants
references:
    - https://github.com/BishopFox/sliver/blob/79f2d48fcdfc2bee4713b78d431ea4b27f733f30/implant/sliver/shell/shell_windows.go#L36
    - https://www.microsoft.com/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/
author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
date: 2022-08-25
modified: 2023-03-05
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```
