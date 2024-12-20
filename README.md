# DBench
Continuous Latency Monitoring through Open RAN Interfaces


## Overview

DBench is a framework designed to automate data collection and analysis for inferring the processing latency of individual RAN components. It interposes on open RAN interfaces to periodically collect user data traffic and correlates these data points to provide a detailed breakdown of user-perceived network latency.

This repository contains the implementation of DBench as described in our paper. It offers tools and workflows to analyze RAN traffic, focusing on the breakdown of latencies across different components.

## Key Features

- Automated Data Collection  
  Collect user data traffic from open RAN interfaces using `Ansible`.
- Latency Correlation and Breakdown  
  Correlate collected data to infer processing delays at the component level.
  Provide insights into user-perceived network latency in open RAN setups.

## Use Cases

DBench has been evaluated on an academic open RAN testbed with several use cases to showcase its capabilities. It has been used to:

- Identify latency bottlenecks in RAN components.
- Analyze fronthaul and backhaul latency contributions.
- Support experiments for enhancing RAN performance.

## Citation

```biblatex
@inproceedings{2024-5GMeMU-DBench,
    author = {Satis Kumar Permal and Yixi Chen and Xin Zhe Khooi and Biqing Qiu and Mun Choon Chan},
    title = {{Towards Continuous Latency Monitoring through Open RAN Interfaces}},
    year = {2024},
    booktitle = {Proceedings of the 4th ACM Workshop on 5G and Beyond Network Measurements, Modeling, and Use Cases},
}
```

## Contact

For questions, feedback, or collaboration inquiries, please reach out to:

    Satis Kumar Permal: satis [at] comp [dot] nus [dot] edu [dot] sg
    Yixi Chen: chenyx [at] comp [dot] nus [dot] edu [dot] sg
    Xin Zhe KHOOI: khooixz [at] comp [dot] nus [dot] edu [dot] sg