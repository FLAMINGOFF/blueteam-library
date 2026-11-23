---
title: Telegram Bot API Request
summary: Detects suspicious DNS queries to api.telegram.org used by Telegram Bots of any kind
sigma_id: c64c5175-5189-431b-a55e-6d9882158251
status: test
level: medium
platform: other
logsource: dns
tactics:
  - TA0011
techniques:
  - T1102.002
author: Florian Roth (Nextron Systems)
date: '2018-06-05'
modified: '2022-10-09'
falsepositives:
  - Legitimate use of Telegram bots in the company
references:
  - https://core.telegram.org/bots/faq
  - https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
  - https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
  - https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/network/dns/net_dns_susp_telegram_api.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Telegram Bot API Request
id: c64c5175-5189-431b-a55e-6d9882158251
status: test
description: Detects suspicious DNS queries to api.telegram.org used by Telegram Bots of any kind
references:
    - https://core.telegram.org/bots/faq
    - https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
    - https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
    - https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/
author: Florian Roth (Nextron Systems)
date: 2018-06-05
modified: 2022-10-09
tags:
    - attack.command-and-control
    - attack.t1102.002
logsource:
    category: dns
detection:
    selection:
        query: 'api.telegram.org'   # Telegram Bot API Request https://core.telegram.org/bots/faq
    condition: selection
falsepositives:
    - Legitimate use of Telegram bots in the company
level: medium
```
