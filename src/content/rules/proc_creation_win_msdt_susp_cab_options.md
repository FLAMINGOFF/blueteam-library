---
title: Suspicious Cabinet File Execution Via Msdt.EXE
summary: Detects execution of msdt.exe using the "cab" flag which could indicates suspicious diagcab files with embedded answer files leveraging CVE-2022-30190
sigma_id: dc4576d4-7467-424f-9eee-fd2b02855fe0
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1202
author: Nasreddine Bencherchali (Nextron Systems), GossiTheDog, frack113
date: '2022-06-21'
modified: '2024-03-13'
falsepositives:
  - Legitimate usage of ".diagcab" files
references:
  - https://twitter.com/nas_bench/status/1537896324837781506
  - https://github.com/GossiTheDog/ThreatHunting/blob/e85884abbf05d5b41efc809ea6532b10b45bd05c/AdvancedHuntingQueries/DogWalk-DiagCab
  - https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-9015912909545e72ed42cbac4d1e96295e8964579c406d23fd9c47a8091576a0
  - https://irsl.medium.com/the-trouble-with-microsofts-troubleshooters-6e32fc80b8bd
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_msdt_susp_cab_options.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Cabinet File Execution Via Msdt.EXE
id: dc4576d4-7467-424f-9eee-fd2b02855fe0
related:
    - id: 6545ce61-a1bd-4119-b9be-fcbee42c0cf3
      type: obsolete
status: test
description: Detects execution of msdt.exe using the "cab" flag which could indicates suspicious diagcab files with embedded answer files leveraging CVE-2022-30190
references:
    - https://twitter.com/nas_bench/status/1537896324837781506
    - https://github.com/GossiTheDog/ThreatHunting/blob/e85884abbf05d5b41efc809ea6532b10b45bd05c/AdvancedHuntingQueries/DogWalk-DiagCab
    - https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-9015912909545e72ed42cbac4d1e96295e8964579c406d23fd9c47a8091576a0
    - https://irsl.medium.com/the-trouble-with-microsofts-troubleshooters-6e32fc80b8bd
author: Nasreddine Bencherchali (Nextron Systems), GossiTheDog, frack113
date: 2022-06-21
modified: 2024-03-13
tags:
    - attack.stealth
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\msdt.exe'
        - OriginalFileName: 'msdt.exe'
    selection_cmd:
        CommandLine|contains|windash: ' -cab '
    condition: all of selection_*
falsepositives:
    - Legitimate usage of ".diagcab" files
level: medium
```
