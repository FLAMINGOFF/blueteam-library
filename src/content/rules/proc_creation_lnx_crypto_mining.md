---
title: Linux Crypto Mining Indicators
summary: Detects command line parameters or strings often used by crypto miners
sigma_id: 9069ea3c-b213-4c52-be13-86506a227ab1
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0040
techniques:
  - T1496
author: Florian Roth (Nextron Systems)
date: '2021-10-26'
modified: '2022-12-25'
falsepositives:
  - Legitimate use of crypto miners
references:
  - https://www.poolwatch.io/coin/monero
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_crypto_mining.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Linux Crypto Mining Indicators
id: 9069ea3c-b213-4c52-be13-86506a227ab1
status: test
description: Detects command line parameters or strings often used by crypto miners
references:
    - https://www.poolwatch.io/coin/monero
author: Florian Roth (Nextron Systems)
date: 2021-10-26
modified: 2022-12-25
tags:
    - attack.impact
    - attack.t1496
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - ' --cpu-priority='
            - '--donate-level=0'
            - ' -o pool.'
            - ' --nicehash'
            - ' --algo=rx/0 '
            - 'stratum+tcp://'
            - 'stratum+udp://'
            # Sub process started by xmrig - the most popular Monero crypto miner - unknown if this causes any false positives
            - 'sh -c /sbin/modprobe msr allow_writes=on'
            # base64 encoded: --donate-level=
            - 'LS1kb25hdGUtbGV2ZWw9'
            - '0tZG9uYXRlLWxldmVsP'
            - 'tLWRvbmF0ZS1sZXZlbD'
            # base64 encoded: stratum+tcp:// and stratum+udp://
            - 'c3RyYXR1bSt0Y3A6Ly'
            - 'N0cmF0dW0rdGNwOi8v'
            - 'zdHJhdHVtK3RjcDovL'
            - 'c3RyYXR1bSt1ZHA6Ly'
            - 'N0cmF0dW0rdWRwOi8v'
            - 'zdHJhdHVtK3VkcDovL'
    condition: selection
falsepositives:
    - Legitimate use of crypto miners
level: high
```
