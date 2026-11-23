---
title: OS Architecture Discovery Via Grep
summary: Detects the use of grep to identify information about the operating system architecture. Often combined beforehand with the execution of "uname" or "cat /proc/cpuinfo"
sigma_id: d27ab432-2199-483f-a297-03633c05bae6
status: test
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0007
techniques:
  - T1082
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: '2023-06-02'
falsepositives:
  - Unknown
references:
  - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
  - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
  - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
  - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_grep_os_arch_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: OS Architecture Discovery Via Grep
id: d27ab432-2199-483f-a297-03633c05bae6
status: test
description: |
    Detects the use of grep to identify information about the operating system architecture. Often combined beforehand with the execution of "uname" or "cat /proc/cpuinfo"
references:
    - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
    - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
    - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
    - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-06-02
tags:
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: linux
detection:
    selection_process:
        Image|endswith: '/grep'
    selection_architecture:
        CommandLine|endswith:
            - 'aarch64'
            - 'arm'
            - 'i386'
            - 'i686'
            - 'mips'
            - 'x86_64'
    condition: all of selection_*
falsepositives:
    - Unknown
level: low
```
