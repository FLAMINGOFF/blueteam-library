---
title: DNS TXT Answer with Possible Execution Strings
summary: Detects strings used in command execution in DNS TXT Answer
sigma_id: 8ae51330-899c-4641-8125-e39f2e07da72
status: test
level: high
platform: other
logsource: dns
tactics:
  - TA0011
techniques:
  - T1071.004
author: Markus Neis
date: '2018-08-08'
modified: '2021-11-27'
falsepositives:
  - Unknown
references:
  - https://twitter.com/stvemillertime/status/1024707932447854592
  - https://github.com/samratashok/nishang/blob/414ee1104526d7057f9adaeee196d91ae447283e/Backdoors/DNS_TXT_Pwnage.ps1
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/network/dns/net_dns_susp_txt_exec_strings.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: DNS TXT Answer with Possible Execution Strings
id: 8ae51330-899c-4641-8125-e39f2e07da72
status: test
description: Detects strings used in command execution in DNS TXT Answer
references:
    - https://twitter.com/stvemillertime/status/1024707932447854592
    - https://github.com/samratashok/nishang/blob/414ee1104526d7057f9adaeee196d91ae447283e/Backdoors/DNS_TXT_Pwnage.ps1
author: Markus Neis
date: 2018-08-08
modified: 2021-11-27
tags:
    - attack.command-and-control
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection:
        record_type: 'TXT'
        answer|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'cmd.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
