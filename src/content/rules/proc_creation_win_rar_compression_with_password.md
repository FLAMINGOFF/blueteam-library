---
title: Rar Usage with Password and Compression Level
summary: Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions.
sigma_id: faa48cae-6b25-4f00-a094-08947fef582f
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1560.001
author: '@ROxPinTeddy'
date: '2020-05-12'
modified: '2022-03-16'
falsepositives:
  - Legitimate use of Winrar command line version
  - Other command line tools, that use these flags
references:
  - https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/
  - https://ss64.com/bash/rar.html
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rar_compression_with_password.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Rar Usage with Password and Compression Level
id: faa48cae-6b25-4f00-a094-08947fef582f
status: test
description: Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions.
references:
    - https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/
    - https://ss64.com/bash/rar.html
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
author: '@ROxPinTeddy'
date: 2020-05-12
modified: 2022-03-16
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_password:
        CommandLine|contains: ' -hp'
    selection_other:
        CommandLine|contains:
            - ' -m'
            - ' a '
    condition: selection_password and selection_other
falsepositives:
    - Legitimate use of Winrar command line version
    - Other command line tools, that use these flags
level: high
```
