---
title: Potential Product Reconnaissance Via Wmic.EXE
summary: Detects the execution of WMIC in order to get a list of firewall and antivirus products
sigma_id: 15434e33-5027-4914-88d5-3d4145ec25a9
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1047
author: Nasreddine Bencherchali
date: '2023-02-14'
modified: '2025-12-15'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2023/03/06/2022-year-in-review/
  - https://www.yeahhub.com/list-installed-programs-version-path-windows/
  - https://learn.microsoft.com/en-us/answers/questions/253555/software-list-inventory-wmic-product
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wmic_recon_product.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Product Reconnaissance Via Wmic.EXE
id: 15434e33-5027-4914-88d5-3d4145ec25a9
status: test
description: Detects the execution of WMIC in order to get a list of firewall and antivirus products
references:
    - https://thedfirreport.com/2023/03/06/2022-year-in-review/
    - https://www.yeahhub.com/list-installed-programs-version-path-windows/
    - https://learn.microsoft.com/en-us/answers/questions/253555/software-list-inventory-wmic-product
author: Nasreddine Bencherchali
date: 2023-02-14
modified: 2025-12-15
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\wmic.exe'
        - OriginalFileName: 'wmic.exe'
    selection_cli:
        CommandLine|contains: 'Product'
    filter_main_call_operations:
        # wmic /node:"#{node}" product where "name like '#{product}%%'" call uninstall
        CommandLine|contains:
            - ' uninstall'
            - ' install'
    filter_main_csproduct:
        # wmic /node:"#{node}" csproduct get name, identifyingnumber, uuid
        # covered by 3e3ceccd-6c06-48b8-b5ff-ab1d25db8c1d
        CommandLine|contains: 'csproduct'
    condition: all of selection_* and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_wmic_recon_product/info.yml
```
