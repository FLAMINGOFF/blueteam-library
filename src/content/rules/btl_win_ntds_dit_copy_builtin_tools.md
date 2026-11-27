---
title: NTDS.dit Copied With Built-In Tools
summary: |-
  Detects command lines that copy the Active Directory database file ntds.dit, usually out of a volume shadow copy, with built-in tools such as copy, xcopy, robocopy, esentutl or PowerShell Copy-Item.
  Together with the SYSTEM hive this gives an attacker offline access to every password hash in the domain.
sigma_id: 4426f76b-9df6-4f4b-bee0-c5d01b77c35b
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.003
author: FLAMINGOFF
date: '2026-11-27'
falsepositives:
  - Documented AD backup scripts (backups normally use ntdsutil IFM or Windows Server Backup, not these tools)
references:
  - https://attack.mitre.org/techniques/T1003/003/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/esentutl
source:
  name: Blue Team Library
  url: https://github.com/FLAMINGOFF/blueteam-library/blob/main/src/content/rules/btl_win_ntds_dit_copy_builtin_tools.md
  license: Original
format: Sigma
original: true
title_zh: 使用系统自带工具复制 NTDS.dit
summary_zh: 检测用 copy、xcopy、robocopy、esentutl 或 PowerShell Copy-Item 等自带工具复制 Active Directory 数据库文件 ntds.dit 的命令行，通常是从卷影副本里拷出来。配合 SYSTEM 注册表配置单元，攻击者就能离线拿到域内所有账户的密码哈希。
notes_zh: 前一步常见的是 vssadmin create shadow 或 wmic shadowcopy call create，可以和本规则按主机、时间关联，提高置信度。
notes_en: The step before is often vssadmin create shadow or wmic shadowcopy call create; correlating with it by host and time raises confidence.
samples:
  - name:
      zh: 从卷影副本复制到 Temp
      en: Copy out of a shadow copy into Temp
    expect: true
    event:
      EventID: 1
      Image: C:\Windows\System32\cmd.exe
      CommandLine: cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\NTDS\ntds.dit C:\Windows\Temp\n.dit
      User: CORP\adm-it
  - name:
      zh: esentutl 拷贝
      en: Copy with esentutl
    expect: true
    event:
      EventID: 1
      Image: C:\Windows\System32\esentutl.exe
      OriginalFileName: esentutl.exe
      CommandLine: esentutl.exe /y /vss C:\Windows\NTDS\ntds.dit /d C:\Users\Public\ntds.dit
  - name:
      zh: 用 ntdsutil 做 IFM 备份（不在本规则范围）
      en: ntdsutil IFM backup (out of scope)
    expect: false
    event:
      EventID: 1
      Image: C:\Windows\System32\ntdsutil.exe
      CommandLine: ntdsutil "ac i ntds" "ifm" "create full C:\IFM" q q
  - name:
      zh: 只是列出 NTDS 目录
      en: Only lists the NTDS folder
    expect: false
    event:
      EventID: 1
      Image: C:\Windows\System32\cmd.exe
      CommandLine: cmd.exe /c dir C:\Windows\NTDS\ntds.dit
---

```yaml
title: NTDS.dit Copied With Built-In Tools
id: 4426f76b-9df6-4f4b-bee0-c5d01b77c35b
status: experimental
description: |
  Detects command lines that copy the Active Directory database file ntds.dit, usually out of a volume shadow copy, with built-in tools such as copy, xcopy, robocopy, esentutl or PowerShell Copy-Item.
  Together with the SYSTEM hive this gives an attacker offline access to every password hash in the domain.
references:
  - https://attack.mitre.org/techniques/T1003/003/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/esentutl
author: FLAMINGOFF
date: 2026-11-27
tags:
  - attack.credential-access
  - attack.t1003.003
logsource:
  category: process_creation
  product: windows
detection:
  selection_file:
    CommandLine|contains: 'ntds.dit'
  selection_tool:
    - Image|endswith:
        - '\cmd.exe'
        - '\xcopy.exe'
        - '\robocopy.exe'
        - '\esentutl.exe'
        - '\powershell.exe'
        - '\pwsh.exe'
    - OriginalFileName:
        - 'XCOPY.EXE'
        - 'robocopy.exe'
        - 'esentutl.exe'
  selection_verb:
    CommandLine|contains:
      - 'copy '
      - 'Copy-Item'
      - 'robocopy'
      - 'esentutl'
      - ' cp '
  condition: all of selection_*
falsepositives:
  - Documented AD backup scripts (backups normally use ntdsutil IFM or Windows Server Backup, not these tools)
level: high
```
