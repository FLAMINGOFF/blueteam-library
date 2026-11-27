---
title: Defender Exclusion Added For A User-Writable Path Via PowerShell
summary: |-
  Detects PowerShell adding a Microsoft Defender path or process exclusion that points into a user-writable directory.
  Malware and hands-on-keyboard operators exclude their staging folder so later payloads are never scanned.
sigma_id: 4447aca4-46b2-4d4f-9ed2-2aa27944b2a7
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
  - TA0112
techniques:
  - T1564.012
  - T1685
author: FLAMINGOFF
date: '2026-11-27'
falsepositives:
  - Software deployment tools that exclude their own cache folder (should be rare and documented)
references:
  - https://attack.mitre.org/techniques/T1564/012/
  - https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference
source:
  name: Blue Team Library
  url: https://github.com/FLAMINGOFF/blueteam-library/blob/main/src/content/rules/btl_win_defender_exclusion_user_writable_path.md
  license: Original
format: Sigma
original: true
title_zh: 通过 PowerShell 为用户可写路径添加 Defender 排除项
summary_zh: 检测 PowerShell 给 Microsoft Defender 添加路径或进程排除项，且排除的位置是用户可写目录。恶意软件和手动操作的攻击者会排除自己的暂存目录，让后续载荷永远不被扫描。
notes_zh: 建议同时监控 Defender 的 5007 事件（配置变更）和注册表 HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions，覆盖不经过 PowerShell 命令行的改法。
notes_en: Also watch Defender event 5007 (configuration changed) and the registry key HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions to catch changes that do not go through a PowerShell command line.
samples:
  - name:
      zh: 排除 ProgramData 下的目录
      en: Excludes a folder under ProgramData
    expect: true
    event:
      EventID: 1
      Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
      OriginalFileName: PowerShell.EXE
      CommandLine: powershell.exe -nop -w hidden -c Add-MpPreference -ExclusionPath "C:\ProgramData\Microsoft\Crypto\cache"
      User: CORP\svc-backup
  - name:
      zh: 排除 TEMP 环境变量路径
      en: Excludes the TEMP variable path
    expect: true
    event:
      EventID: 1
      Image: C:\Program Files\PowerShell\7\pwsh.exe
      OriginalFileName: pwsh.dll
      CommandLine: pwsh -c "Set-MpPreference -ExclusionPath $env:TEMP"
  - name:
      zh: 排除构建服务器的工作目录（不在规则范围内）
      en: Excludes a build agent work folder (out of scope)
    expect: false
    event:
      EventID: 1
      Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
      CommandLine: powershell.exe Add-MpPreference -ExclusionPath D:\BuildAgent\_work
  - name:
      zh: 只是查看当前配置
      en: Only reads the current settings
    expect: false
    event:
      EventID: 1
      Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
      CommandLine: powershell.exe Get-MpPreference | Select ExclusionPath
---

```yaml
title: Defender Exclusion Added For A User-Writable Path Via PowerShell
id: 4447aca4-46b2-4d4f-9ed2-2aa27944b2a7
status: experimental
description: |
  Detects PowerShell adding a Microsoft Defender path or process exclusion that points into a user-writable directory.
  Malware and hands-on-keyboard operators exclude their staging folder so later payloads are never scanned.
references:
  - https://attack.mitre.org/techniques/T1564/012/
  - https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference
author: FLAMINGOFF
date: 2026-11-27
tags:
  - attack.stealth
  - attack.defense-impairment
  - attack.t1564.012
  - attack.t1685
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith:
        - '\powershell.exe'
        - '\pwsh.exe'
    - OriginalFileName:
        - 'PowerShell.EXE'
        - 'pwsh.dll'
  selection_cmdlet:
    CommandLine|contains:
      - 'Add-MpPreference'
      - 'Set-MpPreference'
  selection_param:
    CommandLine|contains:
      - 'ExclusionPath'
      - 'ExclusionProcess'
  selection_path:
    CommandLine|contains:
      - '\Users\Public'
      - '\ProgramData'
      - '\AppData\'
      - '\Windows\Temp'
      - '$env:TEMP'
      - '$env:APPDATA'
      - '$env:PUBLIC'
      - '$env:ProgramData'
  condition: all of selection_*
falsepositives:
  - Software deployment tools that exclude their own cache folder (should be rare and documented)
level: high
```
