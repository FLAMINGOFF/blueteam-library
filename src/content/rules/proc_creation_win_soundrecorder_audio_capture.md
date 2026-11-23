---
title: Audio Capture via SoundRecorder
summary: Detect attacker collecting audio via SoundRecorder application.
sigma_id: 83865853-59aa-449e-9600-74b9d89a6d6e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1123
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
date: '2019-10-24'
modified: '2021-11-27'
falsepositives:
  - Legitimate audio capture by legitimate user.
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1123/T1123.md
  - https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_soundrecorder_audio_capture.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Audio Capture via SoundRecorder
id: 83865853-59aa-449e-9600-74b9d89a6d6e
status: test
description: Detect attacker collecting audio via SoundRecorder application.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1123/T1123.md
    - https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
date: 2019-10-24
modified: 2021-11-27
tags:
    - attack.collection
    - attack.t1123
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\SoundRecorder.exe'
        CommandLine|contains: '/FILE'
    condition: selection
falsepositives:
    - Legitimate audio capture by legitimate user.
level: medium
```
