---
title: Shadow Copies Deletion Using Operating Systems Utilities
summary: Shadow Copies deletion using operating systems utilities
sigma_id: c947b146-0abc-4c87-9c64-b17e9d7274a2
status: stable
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0040
techniques:
  - T1070
  - T1490
author: Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades)
date: '2019-10-22'
modified: '2022-11-03'
falsepositives:
  - Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason
  - LANDesk LDClient Ivanti-PSModule (PS EncodedCommand)
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
  - https://blog.talosintelligence.com/2017/05/wannacry.html
  - https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/
  - https://www.bleepingcomputer.com/news/security/why-everyone-should-disable-vssadmin-exe-now/
  - https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
  - https://github.com/Neo23x0/Raccine#the-process
  - https://github.com/Neo23x0/Raccine/blob/20a569fa21625086433dcce8bb2765d0ea08dcb6/yara/gen_ransomware_command_lines.yar
  - https://redcanary.com/blog/intelligence-insights-october-2021/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
title_zh: 删除卷影副本
summary_zh: 检测使用操作系统自带工具删除卷影副本的行为。
featured: true
---

```yaml
title: Shadow Copies Deletion Using Operating Systems Utilities
id: c947b146-0abc-4c87-9c64-b17e9d7274a2
status: stable
description: Shadow Copies deletion using operating systems utilities
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - https://blog.talosintelligence.com/2017/05/wannacry.html
    - https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/
    - https://www.bleepingcomputer.com/news/security/why-everyone-should-disable-vssadmin-exe-now/
    - https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
    - https://github.com/Neo23x0/Raccine#the-process
    - https://github.com/Neo23x0/Raccine/blob/20a569fa21625086433dcce8bb2765d0ea08dcb6/yara/gen_ransomware_command_lines.yar
    - https://redcanary.com/blog/intelligence-insights-october-2021/
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/blackbyte-exbyte-ransomware
author: Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades)
date: 2019-10-22
modified: 2022-11-03
tags:
    - attack.impact
    - attack.stealth
    - attack.t1070
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection1_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\wmic.exe'
              - '\vssadmin.exe'
              - '\diskshadow.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
              - 'wmic.exe'
              - 'VSSADMIN.EXE'
              - 'diskshadow.exe'
    selection1_cli:
        CommandLine|contains|all:
            - 'shadow'  # will match "delete shadows" and "shadowcopy delete" and "shadowstorage"
            - 'delete'
    selection2_img:
        - Image|endswith: '\wbadmin.exe'
        - OriginalFileName: 'WBADMIN.EXE'
    selection2_cli:
        CommandLine|contains|all:
            - 'delete'
            - 'catalog'
            - 'quiet' # will match -quiet or /quiet
    selection3_img:
        - Image|endswith: '\vssadmin.exe'
        - OriginalFileName: 'VSSADMIN.EXE'
    selection3_cli:
        CommandLine|contains|all:
            - 'resize'
            - 'shadowstorage'
        CommandLine|contains:
            - 'unbounded'
            - '/MaxSize='
    condition: (all of selection1*) or (all of selection2*) or (all of selection3*)
falsepositives:
    - Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason
    - LANDesk LDClient Ivanti-PSModule (PS EncodedCommand)
level: high
```
