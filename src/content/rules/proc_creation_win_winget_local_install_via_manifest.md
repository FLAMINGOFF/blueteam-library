---
title: Install New Package Via Winget Local Manifest
summary: |-
  Detects usage of winget to install applications via manifest file. Adversaries can abuse winget to download payloads remotely and execute them.
  The manifest option enables you to install an application by passing in a YAML file directly to the client.
  Winget can be used to download and install exe, msi or msix files later.
sigma_id: 313d6012-51a0-4d93-8dfc-de8553239e25
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Sreeman, Florian Roth (Nextron Systems), frack113
date: '2020-04-21'
modified: '2023-04-17'
falsepositives:
  - Some false positives are expected in some environment that may use this functionality to install and test their custom applications
references:
  - https://learn.microsoft.com/en-us/windows/package-manager/winget/install#local-install
  - https://lolbas-project.github.io/lolbas/Binaries/Winget/
  - https://web.archive.org/web/20250828100901/https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_winget_local_install_via_manifest.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Install New Package Via Winget Local Manifest
id: 313d6012-51a0-4d93-8dfc-de8553239e25
status: test
description: |
    Detects usage of winget to install applications via manifest file. Adversaries can abuse winget to download payloads remotely and execute them.
    The manifest option enables you to install an application by passing in a YAML file directly to the client.
    Winget can be used to download and install exe, msi or msix files later.
references:
    - https://learn.microsoft.com/en-us/windows/package-manager/winget/install#local-install
    - https://lolbas-project.github.io/lolbas/Binaries/Winget/
    - https://web.archive.org/web/20250828100901/https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget
author: Sreeman, Florian Roth (Nextron Systems), frack113
date: 2020-04-21
modified: 2023-04-17
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\winget.exe'
        - OriginalFileName: 'winget.exe'
    selection_install_flag:
        CommandLine|contains:
            - 'install'
            - ' add ' # https://github.com/microsoft/winget-cli/blob/02d2f93807c9851d73eaacb4d8811a76b64b7b01/src/AppInstallerCLICore/Commands/InstallCommand.h
    selection_manifest_flag:
        CommandLine|contains:
            - '-m '
            - '--manifest'
    condition: all of selection_*
falsepositives:
    - Some false positives are expected in some environment that may use this functionality to install and test their custom applications
level: medium
```
