---
title: Scheduled Task Created To Run From A User-Writable Path
summary: |-
  Detects schtasks.exe creating a task whose action points into a user-writable location such as Public, ProgramData, AppData or Temp.
  Persistence through scheduled tasks usually points at a payload the attacker could write without admin rights.
sigma_id: fc2c9a15-a856-4030-940b-d90f72ae7a77
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0003
  - TA0004
techniques:
  - T1053.005
author: FLAMINGOFF
date: '2026-11-27'
falsepositives:
  - Per-user software updaters that register tasks pointing into AppData
references:
  - https://attack.mitre.org/techniques/T1053/005/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
source:
  name: Blue Team Library
  url: https://github.com/FLAMINGOFF/blueteam-library/blob/main/src/content/rules/btl_win_schtasks_create_user_writable_path.md
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
original: true
title_zh: 创建从用户可写路径启动程序的计划任务
summary_zh: 检测 schtasks.exe 创建计划任务，且任务要运行的程序位于 Public、ProgramData、AppData、Temp 等用户可写位置。通过计划任务做持久化时，载荷通常放在不需要管理员权限就能写入的目录。
notes_zh: 调优建议：常见误报是浏览器、协作软件等按用户安装的自动更新程序。可按任务名或程序路径把这些厂商加入 filter_optional_*，不要直接排除整个 AppData。
notes_en: 'Tuning: expect noise from per-user auto-updaters (browsers, collaboration tools). Add them to filter_optional_* by task name or exact path rather than excluding all of AppData.'
samples:
  - name:
      zh: 每次登录运行 Public 下的程序
      en: Runs a Public binary at every logon
    expect: true
    event:
      EventID: 1
      Image: C:\Windows\System32\schtasks.exe
      OriginalFileName: schtasks.exe
      CommandLine: schtasks /create /sc onlogon /tn "OneDrive Sync Helper" /tr C:\Users\Public\svc.exe /f
      ParentImage: C:\Windows\System32\cmd.exe
  - name:
      zh: 连字符参数，程序在 AppData
      en: Dash-style flags
      binary in AppData: null
    expect: true
    event:
      EventID: 1
      Image: C:\Windows\System32\schtasks.exe
      CommandLine: schtasks.exe -create -sc minute -mo 30 -tn Updater -tr "C:\Users\bob\AppData\Roaming\upd\upd.exe"
  - name:
      zh: OneDrive 自带的更新任务（排除）
      en: OneDrive's own update task (filtered)
    expect: false
    event:
      EventID: 1
      Image: C:\Windows\System32\schtasks.exe
      CommandLine: schtasks /create /tn "OneDrive Standalone Update Task" /tr "C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe" /sc daily
  - name:
      zh: 查询任务（不是创建）
      en: Querying tasks
      not creating: null
    expect: false
    event:
      EventID: 1
      Image: C:\Windows\System32\schtasks.exe
      CommandLine: schtasks /query /fo LIST /v
---

```yaml
title: Scheduled Task Created To Run From A User-Writable Path
id: fc2c9a15-a856-4030-940b-d90f72ae7a77
status: experimental
description: |
  Detects schtasks.exe creating a task whose action points into a user-writable location such as Public, ProgramData, AppData or Temp.
  Persistence through scheduled tasks usually points at a payload the attacker could write without admin rights.
references:
  - https://attack.mitre.org/techniques/T1053/005/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
author: FLAMINGOFF
date: 2026-11-27
tags:
  - attack.execution
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\schtasks.exe'
    - OriginalFileName: 'schtasks.exe'
  selection_create:
    CommandLine|contains|windash: ' /create '
  selection_path:
    CommandLine|contains:
      - '\Users\Public\'
      - '\ProgramData\'
      - '\AppData\'
      - '\Windows\Temp\'
      - '\PerfLogs\'
      - '%PUBLIC%'
      - '%APPDATA%'
      - '%LOCALAPPDATA%'
      - '%TEMP%'
  filter_optional_onedrive:
    CommandLine|contains: '\AppData\Local\Microsoft\OneDrive\'
  condition: all of selection_* and not 1 of filter_optional_*
falsepositives:
  - Per-user software updaters that register tasks pointing into AppData
level: medium
```
