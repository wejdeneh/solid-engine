# Cloud-Native Security for 5G

## Content

- [Cloud-Native Security for 5G](#cloud-native-security-for-5g)
  - [Content](#content)
  - [Introduction](#introduction)
    - [5G](#5g)
      - [The 5G Primitives](#the-5g-primitives)
    - [Motivation of 5G cloud-native application](#motivation-of-5g-cloud-native-application)
      - [Key Cloud Advantages for 5G](#key-cloud-advantages-for-5g)
    - [BubbleRan](#bubbleran)
      - [Key Components](#key-components)
    - [5G cluster](#5g-cluster)
    - [5G cloud-native security](#5g-cloud-native-security)
  - [KubeArmor](#kubearmor)
    - [KubeArmor Architecture](#kubearmor-architecture)
    - [Enforcer](#enforcer)
    - [Policy Application Behavior](#policy-application-behavior)
    - [Policy Log format](#policy-log-format)
    - [KubeArmor Policy](#kubearmor-policy)
      - [Policy Specification](#policy-specification)
    - [KubeArmor Default Security Posture](#kubearmor-default-security-posture)
    - [Policy Conflict Action in Whitelist](#policy-conflict-action-in-whitelist)
  - [Nested Policy Structure](#nested-policy-structure)
    - [Real Policy structure](#real-policy-structure)
  - [Policy Operations](#policy-operations)
  - [Define policies](#define-policies)
    - [Hardening policies](#hardening-policies)
    - [The applied policies](#the-applied-policies)
    - [Methodology of defining a KubeArmor Policy](#methodology-of-defining-a-kubearmor-policy)
      - [Define a policy according to the KubeArmor log](#define-a-policy-according-to-the-kubearmor-log)
  - [Experiment Based on Microk8s](#experiment-based-on-microk8s)
    - [Environment Description](#environment-description)
    - [Result](#result)
    - [The reason for 5G network cluster crash](#the-reason-for-5g-network-cluster-crash)
      - [VM snapshot file system Comparison experiment](#vm-snapshot-file-system-comparison-experiment)
        - [Comparison](#comparison)
    - [Analysis](#analysis)
  - [Experiment Based on Kubeadm](#experiment-based-on-kubeadm)
    - [Environment Description](#environment-description-1)
    - [Result](#result-1)
    - [Analysis](#analysis-1)
  - [Conclusion](#conclusion)
  - [TODO](#todo)
  - [Appendix](#appendix)


## Introduction

### 5G

5G refers to the fifth generation of mobile network technology. It represents the latest evolution in wireless communication standards, succeeding 4G/LTE technology. 5G promises significantly faster data speeds, lower latency, increased capacity, and improved connectivity compared to previous generations.

#### The 5G Primitives

![5G-services](doc/res/5G-services.webp)

- Enhanced Mobile Broadband (eMBB)
  - Focus: High data rates, high capacity, and mobility.
  - Use cases: AR/VR, cloud gaming, real-time data transfers.
- Massive Machine Type Communications (mMTC)
  - Focus: Connecting a vast number of low-power, low-data devices efficiently.
  - Use cases: industrial monitoring, environmental data collection
- Ultra-Reliable and Low-latency Communications (uRLLC)
  - Focus: Mission-critical applications requiring guaranteed reliability and minimal latency.
  - Use cases: Autonomous vehicles

### Motivation of 5G cloud-native application

The advent of 5G networks demands infrastructure capable of supporting unprecedented mobility, latency, and bandwidth demands. With its inherent attributes, cloud technology emerges as a pivotal enabler in realizing the full potential of 5G.

#### Key Cloud Advantages for 5G

- Containerization: By encapsulating network functions (NFs) in self-contained, portable containers, 5G infrastructure gains unprecedented agility. In 5G cloud-native applications, this facilitates rapid deployment, efficient resource utilization, and simplified scaling.
- Dynamic Orchestration: Cloud-based orchestration platforms automate the deployment, management, and scaling of NFs. In 5G cloud-native applications, this translates to dynamic service provisioning, optimized resource allocation, and automated failure recovery, ensuring seamless service delivery amidst network fluctuations.
- Scalability: Cloud infrastructure inherently scales elastically, effortlessly adapting to varying network demands. In 5G cloud-native application, this empowers operators to cater to surges in traffic without provisioning excess capacity, ultimately optimizing resource utilization and minimizing costs.

### BubbleRan

BubbleRAN offers a novel approach to deploying and managing 5G networks. Vendor-neutral telecom networks that are fully software-based and adhere to the
principles of Open RAN. In this project, bubbleRan is used to deploy and manage 5G cluster.

#### Key Components

- T9S Cluster
- Harbor Image Repository
- Basic 5G Cloud Environment

### 5G cluster

A 5G cluster includes six pods in one namespace. It contains three sections:
- User Equipment (UE): nr-rfsim
- Core Network (CN): amf, db, smf, upf
- Radio Access Network (RAN): gnb


### 5G cloud-native security

![cloud-security](doc/res/cloud-security.png)

A 5G cloud-native application, like a normal cloud application, encompasses four core levels: code, container, cluster, and cloud. Each level requires specific strategies and tools to ensure comprehensive protection. In this project, KubeArmor is used to protect the security from the container level to the cluster level.

## KubeArmor

KubeArmoris is a runtime Kubernetes security engine using eBPF and Linux Security Modules(LSM) to enforce policy-based controls.

### KubeArmor Architecture

KubeArmor leverages LSM such as AppArmor, SELinux, or BPF-LSM to enforce the user-specified policies. KubeArmor generates rich alerts/telemetry events with ```container/pod/namespace``` identities by leveraging eBPF.
KubeArmor offers both pre-built policies and allows for creating custom policies tailored to specific needs. When the policy is triggered, an alert will be generated in the log.
Users can use karmor, a KubeArmor CLI tool, to play with KubeArmor.

![KubeArmor High Level Design](doc/res/kubearmor_overview.webp)


### Enforcer

```
● AppArmor
Mandatory Access Control (MAC) system
Uses profiles to define the permissions
```
```
● BPF LSM
Real-time monitoring
Enforce security policy
```
```
AppArmor VS BPF LSM
```
```
AppArmor: confining processes using
profiles based on file paths
```
```
BPF LSM: flexible and dynamic framework
```

### Policy Application Behavior

KubeArmor summarizes the information and provides a user-friendly view to figure out the application behavior, which will be shown in the below picture.

![application behavior](doc/res/app-behavior.png)

### Policy Log format

According to four types of behaviors, KubeArmor provides four types of policies: process, file, network, and capability. However, kubeArmor doesn't support capabilities anymore. An example of the policy log format is shown.

```

{
  "Timestamp": 1707909097,
  "UpdatedTime": "2024-02-14T11:11:37.695048Z",
  "ClusterName": "default",
  "HostName": "edo",
  "NamespaceName": "trirematics",
  "PodName": "oai-amf.core.eurecom-c69f45c8f-lx24c",
  "Labels": "app.kubernetes.io/created-by=athena-base-operator,app.kubernetes.io/managed-by=athena-base-operator,athena.t9s.io/element-name=oai-amf.core.eurecom,app.kubernetes.io/name=amf,app.kubernetes.io/version=v4.1.0-v1.5.1,app.kubernetes.io/instance=TODO,roles.athena.t9s.io/amf=active,app.kubernetes.io/component=oai-amf,app.kubernetes.io/part-of=core.eurecom,roles.athena.t9s.io/cn=active,athena.t9s.io/network=core.eurecom",
  "ContainerID": "afe9a2f76f90c4de1945044be12b5815e5d7907559b80cd81d2511cb496fcbe7",
  "ContainerName": "amf",
  "ContainerImage": "hub.bubbleran.com/oai/oai-cn:v4.1.0-v1.5.1@sha256:37d5a7904727f833e1563c830d1b28d7780b73f327b3f915baf159863d3d96ff",
  "HostPPID": 3608147,
  "HostPID": 3608197,
  "PPID": 3608147,
  "PID": 1,
  "UID": 0,
  "PolicyName": "DefaultPosture",
  "Type": "MatchedPolicy",
  "Operation": "File",
  "Resource": "/run/containerd/io.containerd.runtime.v2.task/k8s.io/cc23aeafb67f3b5e3159ec108fcf55202e00d84d6569df847a439e6e03e285de/rootfs/dev/random",
  "Data": "lsm=FILE_MKNOD",
  "Enforcer": "BPFLSM",
  "Action": "Audit",
  "Result": "Passed",
  "Cwd": "/"
}
```
Here is the explanation for some important fields in the policy log.

| Log field              | Description                                                               | Example                                                                                                       |
|------------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| ClusterName            | gives information about the cluster for which the log was generated       | default                                                                                                       |
| Operation              | gives details about what type of operation happened in the pod            | File or Process or Network                                                                                         |
| ContainerID            | information about the container ID from where log was generated           | afe9a2f76f90c4de1945044be12b5815e5d7907559b80cd81d2511cb496fcbe7                                                                        |
| ContainerImage         | shows the image that was used to spin up the container                    | hub.bubbleran.com/oai/oai-cn:v4.1.0-v1.5.1@sha256:37d5a7904727f833e1563c830d1b28d7780b73f327b3f915baf159863d3d96ff                          |
| ContainerName          | specifies the Container name where the log got generated                  | amf                                                                                              |
| Data                   | shows the system call that was invoked for this operation                 | syscall=SYS_OPENAT fd=-100 flags=O_RDWR\|O_CREAT\|O_NOFOLLOW\|O_CLOEXEC                                       |
| HostName               | shows the node name where the log got generated                           | edo                                                                         |
| HostPID                | gives the host Process ID                                                 | 3608197                                                                                                     |
| HostPPID               | lists the details of host Parent Process ID                                | 3608147                                                                                                       |
| Labels                 | shows the pod label from where log generated                              | app.kubernetes.io/created-by=athena-base-operator,app.kubernetes.io/managed-by=athena-base-operator,athena.t9s.io/element-name=oai-amf.core.eurecom,app.kubernetes.io/name=amf,app.kubernetes.io/version=v4.1.0-v1.5.1,app.kubernetes.io/instance=TODO,roles.athena.t9s.io/amf=active,app.kubernetes.io/component=oai-amf,app.kubernetes.io/part-of=core.eurecom,roles.athena.t9s.io/cn=active,athena.t9s.io/network=core.eurecom                                                                                          |
| Message                | gives the message specified in the policy                                 | Network service has been scanned!                                     |
| NamespaceName          | lists the namespace where the pod is running                                  | trirematics                                                                                             |
| PID                    | lists the process ID running in the container                                 | 1                                                                                                             |
| PPID                   | lists the Parent process ID running in the container                          | 3608147                                                                                                        |
| ParentProcessName      | gives the parent process name from where the operation happened            | /opt/hydra/bin/bash                                                                              |
| PodName                | lists the pod name where the log got generated                            | oai-amf.core.eurecom-c69f45c8f-lx24c                                                                                      |
| ProcessName            | specifies the operation that happened inside the pod for this log         | /opt/hydra/bin/ip                                                                                               |
| Resource               | lists the resources that was requested                                    | /run/containerd/io.containerd.runtime.v2.task/k8s.io/cc23aeafb67f3b5e3159ec108fcf55202e00d84d6569df847a439e6e03e285de/rootfs/dev/random                                                                                             |
| Result                 | shows whether the event was allowed or denied                             | Passed                                                                                                        |
| Source                 | lists the source from where the operation request came                    | /opt/hydra/bin/bash                                                                                               |
| Type                   | specifies it as container log                                             | MatchedPolicy                                                                                                  |
### KubeArmor Policy

There are two types of policies in kubeArmor: KubeArmorPolicy(container) and KubeArmorHostPolicy(virtual machine). In this project, we focus on the container-level policy.

#### Policy Specification

According to the application behaviors, there are four types of policy operations: network, process, file, and capabilities, with system call control operation.

```text
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: [policy name]
  namespace: [namespace name]

spec:
  severity: [1-10]                         # --> optional (1 by default)
  tags: ["tag", ...]                       # --> optional
  message: [message]                       # --> optional

  selector:
    matchLabels:
      [key1]: [value1]
      [keyN]: [valueN]

  process:
    matchPaths:
    - path: [absolute executable path]
      ownerOnly: [true|false]              # --> optional
      fromSource:                          # --> optional
      - path: [absolute exectuable path]
    matchDirectories:
    - dir: [absolute directory path]
      recursive: [true|false]              # --> optional
      ownerOnly: [true|false]              # --> optional
      fromSource:                          # --> optional
      - path: [absolute exectuable path]
    matchPatterns:
    - pattern: [regex pattern]
      ownerOnly: [true|false]              # --> optional

  file:
    matchPaths:
    - path: [absolute file path]
      readOnly: [true|false]               # --> optional
      ownerOnly: [true|false]              # --> optional
      fromSource:                          # --> optional
      - path: [absolute exectuable path]
    matchDirectories:
    - dir: [absolute directory path]
      recursive: [true|false]              # --> optional
      readOnly: [true|false]               # --> optional
      ownerOnly: [true|false]              # --> optional
      fromSource:                          # --> optional
      - path: [absolute exectuable path]
    matchPatterns:
    - pattern: [regex pattern]
      readOnly: [true|false]               # --> optional
      ownerOnly: [true|false]              # --> optional

  network:
    matchProtocols:
    - protocol: [TCP|tcp|UDP|udp|ICMP|icmp]
      fromSource:                          # --> optional
      - path: [absolute exectuable path]

  capabilities:
    matchCapabilities:
    - capability: [capability name]
      fromSource:                          # --> optional
      - path: [absolute exectuable path]
  
  syscalls:
    matchSyscalls:
    - syscall:
      - syscallX
      - syscallY
      fromSource:                            # --> optional
      - path: [absolute exectuable path]
      - dir: [absolute directory path]
        recursive: [true|false]              # --> optional
    matchPaths:
    - path: [absolute directory path | absolute exectuable path]
      recursive: [true|false]                # --> optional
      - syscall:
        - syscallX
        - syscallY
      fromSource:                            # --> optional
      - path: [absolute exectuable path]
      - dir: [absolute directory path]
        recursive: [true|false]              # --> optional

  action: [Allow|Audit|Block] (Block by default)
```


There are three types of matches: **matchPaths**, **matchDirectories**, and **matchPatterns**

In each match, there are three options.

  * ownerOnly (static action: allow owner only; otherwise block all)

    If this is enabled, the owners of the executable(s) defined with matchPaths and matchDirectories will be only allowed to execute.

  * recursive

    If this is enabled, the coverage will extend to the subdirectories of the directory defined with matchDirectories.

  * fromSource

    If a path is specified in fromSource, the executable at the path will be allowed/blocked to execute the executables defined with matchPaths or matchDirectories. For better understanding, let us say that an operator defines a policy as follows. Then, ```/bin/bash``` will be only allowed (blocked) to execute ```/bin/sleep```. Otherwise, the execution of ```/bin/sleep``` will be blocked (allowed).

    ```text
      process:
        matchPaths:
        - path: /bin/sleep
          fromSource:
          - path: /bin/bash
    ```

### KubeArmor Default Security Posture

KubeArmor supports configurable default security posture. The security posture could be `Allow/Audit/Deny`. 

> **_NOTE:_** Default Posture is used when there's at least one `Allow` policy for the given deployment.

Two default modes of operation are available: Block` and `Audit`. `Block` mode blocks all the operations that are not allowed in the policy. **`Audit` generates telemetry events for operations that would have been blocked otherwise**.



By default, KubeArmor sets the global default posture to `audit`.

Global default posture is configured using configuration options passed to KubeArmor using the configuration file

```yaml
defaultFilePosture: block # or audit
defaultNetworkPosture: block # or audit
defaultCapabilitiesPosture: block # or audit
```

Or using command line flags with the KubeArmor binary

```sh
  -defaultFilePosture string
      configuring default enforcement action in global file context [audit,block] (default "block")
  -defaultNetworkPosture string
      configuring default enforcement action in global network context [audit,block] (default "block")
  -defaultCapabilitiesPosture string
      configuring default enforcement action in global capability context [audit,block] (default "block")
```

In this project, we use `audit` as the default posture.

### Policy Conflict Action in Whitelist

For two types of default posture, we define the `Block` default posture as a blacklist and the `Audit` default posture as a whitelist.

Next, we will discuss the policy conflict action in whitelist.

> **_NOTE:_** `Allow` action allows to pass operation without log, the `Audit` action allows to pass operation with log, and the `Block` action blocks the operations with log.

Here is an example.

![example](doc/res/policy_action_conflict.png)

There are two pods: pod A with \(grp=1, role=A\) and pod B with \(grp=1, role=B\). 
There are two policies: policy one blocks matched label \(grp=1\) to run the `/bin/bash` process, and policy two allows matched label \(role=A\) to run the `/app` process.
Then, these two policies will be enforced into Pod A. At this point, Pod A will be only able to execute `/app`.

However, then the whitelist will be activated, which is the `audit` default posture. kubeArmor will generate a log for the part apart from policies one and two.

![action-conflict in whitelist](doc/res/action-conflict.png)

In the end, apart from the block log, the `audit` default posture generates a lot of unrelated logs.

## Nested Policy Structure

To fix too many logs problems mentioned in [Policy Conflict Action in Whitelist](#policy-conflict-action-in-whitelist). Considering `Allow` doesn't generate a log, we want to add another `Allow` policy to replace `Audit` mode. 

![policy structure](doc/res/nested-structure.png)

Then, a nested policy structure is created. Here is the policy structure.

```
(Aduit(Allow(Block(Allow))))
```

In the `Audit` default posture, we first add the `Block` action for a big range. After that, a small range of `Allow` policies will be added. Then, another level of the `Allow` policy is to clean the unrelated logs generated by the whitelist.

A more detailed experiment based on relationship among actions is listed in [Appendix](#appendix).

### Real Policy structure

The actual policy structure is shown under [KubeArmorPolicy](./KubeArmorPolicy/) directory.

1. File named by <action>-<policy_name>
2. Folders are the categorized policies
Blacklist default
    - the first layer of the whitelist is in the same folder as the blacklist.
    - the second level of whitelist is under the `whitelists` folder, which is divided into CN (`allow-CN-whitelist.yaml`), RAN (`allow-RAN-whitelist.yaml`), UE (`allow-UE-whitelist.yaml`), general (`allow-whitelist.yaml`) categories.
3. The audit file doesn't have its own folder yet.
4. For the product, three levels of security are defined. A higher level of security has more security constraints.
   1. No security
   2. Developer Level
   3. Product Level

## Policy Operations

Policy-related operations include creating, updating (modifying), and deleting.

1. Apply/Update Policy
    a. Apply/Update specific: `kubectl apply -f <policy_file_path>`
    b. ApplyUpdate All: A script is provided. More details are in [apply-policy script](../scripts/apply-policy.sh)
2. Delete Policy
    a. Delete specific
        Get policy name: `kubectl get KubeArmorPolicy -A -n <name_space>`
        Delete: `kubectl delete KubeArmorPolicy <name> -n <name_space>`
    b. Delete All
        `kubectl delete --all KubeArmorPolicy -n <name_space>`

## Define policies

This section introduces how to define the hardening policies according to recommendations for karmor and how to define a new policy.

### Hardening policies

Hardening policies are derived from industry-leading compliance standards and attack frameworks such as CIS, MITRE, NIST, STIGs, and several others.

KubeArmor is a security solution for Kubernetes and cloud-native platforms that protect clients' workloads from attacks and threats by providing a set of hardening policies, such as CIS, MITRE, NIST-800-53, and STIGs.

[KubeArmor Policy Templates](https://github.com/kubearmor/policy-templates/) contains the latest hardening policies. karmor, KubeArmor client tool, provides a way (`karmor recommend`) to fetch the policies in the context of the kubernetes workloads or specific container using command line. The output is a set of KubeArmorPolicy or KubeArmorHostPolicy that can be applied using k8s native tools.

The rules in hardening policies are based on inputs from:

- MITRE TTPs
- Security Technical Implementation Guides (STIGs)
- NIST SP 800-53A
- Center for Internet Security (CIS)
- Others

### The applied policies

The recommended hardening policies and the applied policies are shown in [hardening policies](Hardening-policies.md)

In this project, **10** dhardening rules are applied (8 different categories block rules with 2 categories have inside Allow rules and 2 audit rules). For the second layer whitelist, there are around **110** Allow rules. Among them, 36 rules in CN, 21 rules in RAN, 6 rules in UE, and 67 general rules.

### Methodology of defining a KubeArmor Policy

<!-- Methods on how a given audit could be analyzed to be turned into a block or allow rule in the YAML file with scripts and the cycle -->

There are two ways to define a new policy in general. **First**, from a 5G network security specialist to find the vulnerabilities and set a KubeArmor policy. **Second**, according to the log de, fine a new policy.

#### Define a policy according to the KubeArmor log

A flow chart about how a given audit could be analyzed to be turned into a block or allow rule in the YAML file is shown below.

![a-new-audit-log](doc/res/a-new-audit-log.png)

## Experiment Based on Microk8s

### Environment Description

The environment setting is

1. A 5G network cluster is running on Microk8s
2. KubeArmor installed by karmor
3. Default security posture: Audit
4. Enable AppArmor, BPF LSM in the system setting

Here, Microk8s is a lightweight Kubernetes distribution that is designed to run on local systems.

### Result

5G Network cannot be successfully installed in Microk8s with KubeArmor (No policy)

Three crashing situations I met,

1. amf, upf and nr-ntifr crashed
2. upf and nr-ntifr crashed
3. nr-ntifr crashed

It can be concluded that user equipment or user equipment with some parts of the core network of 5G crashed.

### The reason for 5G network cluster crash

About what may cause the crash in the 5G network cluster, we have two different ideas.

1. kubeArmor blocks every pod at some moment
  Verifying process: another pod or deployment is deployed (we choose busybox here) when the 5G network cluster is stuck at installation.
  Result: busybox deploys and works properly
  Therefore, it is not the reason.
2. After adding kubearmor, the system opens so many file descriptors that the cluster cannot create some crucial files at some moment.
  Verifying process: system setting is changed, and file descriptors are set as maximum.
  Result: 5G network cluster still crashed.
  Therefore, it is not the reason.

#### VM snapshot file system Comparison experiment

Given that our two ideas are not the points, a VM snapshot file system Comparison experiment was conducted for deeper exploration, which compares the difference between the file systems without KubeArmor installation, with KubeArmor installation, and with KubeArmor uninstallation.

> **_NOTE:_** There is no policy applied in Kubernetes.

Compare the file systems without KubeArmor installation and with KubeArmor installation to dig out what causes the problem.

Compare the file systems between KubeArmor installation and KubeArmor uninstallation to check if, after uninstalling, there are still some setting changes left in the system.

Here are the steps:

1. Create a VM and enable LSM BPF
2. Install microk8s, karmor
3. Deploy a busybox -> First snapshot: without KubeArmor
4. Install KubeArmor with **Audit** mode default posture -> Second snapshot: with KubeArmor
5. Uninstall KubeArmor -> Third snapshot: after KubeArmor
6. Extract the file systems from snapshots
7. Compare with Beyond Compare
8. Check the KubeArmor log

Three snapshots were created in this experiment.

- Original: mircok8s and karmor (karmor haven't installed kubeArmor).
- Installed Version: mircok8s and karmor with kubeArmor installed.
- Uninstalled Version: Mircok8s and Karmor with kubeArmor are uninstalled.

Different snapshots are shown below.
![vm-snapshots](doc/res/vm-snapshots.png)

##### Comparison

Beyond Compare is used to compare the file system from snapshots.

![compare snapshots](doc/res/beyond-compare.png)

Since KubeArmor will interact with system resources with Linux Security Modules, our focus will be `kern.log`, `sys.log`, container log and KubeArmor log.

When I compared `/var/log/kern.log`, I noticed that KubeArmor used AppArmor as an enforcer and **AppArmor rejected some system calls**.

![kern log](doc/res/kern-log.png)

When I checked the log from KubeArmor, I noticed that a Default Posture policy blocked a file from `/sys/devices/virtual/block/loop0`.

![KubeArmor log](doc/res/kubearmor-log.png)

### Analysis

● When the Kubernetes environment is Microk8s, KubeArmor chooses AppArmor as an enforcer.
Even though Apparmor, BPF LSM, and SE Linux are enabled in the system, KubeArmor used AppArmor as an enforcer.

● When the 5G network cluster tries to install in Mircok8s, it may raise some system call
and AppArmor will try to stop it.
AppArmor's Default posture policy rejected the system call.

## Experiment Based on Kubeadm

### Environment Description


The environment setting is

1. A 5G network cluster is running on Microk8s
2. KubeArmor installed by karmor
3. Default security posture: Audit
4. Enable AppArmor, BPF LSM in the system setting

It is the same environment setting, except this experiment is based on Kubeadm.

Here, Kubeadm is a tool built to provide `kubeadm init` and `kubeadm join` as best-practice "fast paths" for creating Kubernetes clusters.

### Result

| | 5G Cluster without KubeArmor | 5G Cluster with KubeArmor|
|:----|:----|:----|
|MIN (ms) |3.699 |**3.653**|
|MAX (ms) |11.717| **10.392**|
|AVG (ms) |7.124 |**6.332**|
|MEDV (ms)| 1.825 |1.825|
|CPU Usage (%) |**22**| 24|
|Memory Usage (%)| **17** | 18|



| |5G Cluster without KubeArmor |5G Cluster with KubeArmor|
|:----|:----|:----|
|Transfer (MBytes)| **836**| 819|
|Bandwidth (Mbits/sec)| **115** |113|
|Reads=Dist |290299=290099:178:8:8:3:3:0:0 |476548=476302:186:23:16:8:9:1|
|:3|
|Max CPU Usage (%)| 46 |46|
|Avg Memory Usage (%) |18 |18|

| |5G Cluster without KubeArmor|5G Cluster with KubeArmor|
|:----|:----|:----|
|Transfer (MBytes) |268| **270**|
|Bandwidth (Mbits/sec) |35.6| **35.9**|
|Write/Err |2178/0 |2201/0|
|Max CPU Usage (%)| 29| 29|
|Avg Memory Usage (%) |18| 18|

### Analysis

According to the outcome of the Round-trip time test, the download throughput time test, and the upload throughput time test, the overhead introduced by KubeArmor is **negligible**, with only trivial effects on the overall 5G cloud system performance.

## Conclusion

- Create and apply a two-layer whitelist nested kubeArmor policy structure for the 5G cloud.
- The basic policy protection is defined, which is compliant with attack frameworks. More than that, the methodology for defining a new policy is given.
- KubeArmor can protect runtime security from container to cluster while only bringing negligible impact on performance
- The 5G network cluster cannot work with KubeArmor in Microk8s. This is proper because KubeArmor uses AppArmor in Microk8s, and some parts of the 5G network cluster get blocked by AppArmor.

## TODO

1. Complete the [test](Policy-test/test.sh) for checking the policy
2. Zero trust version (Default Posture: Block)
3. KubeArmor with AppArmor in Kubeadm
4. Maintain

## Appendix

[Appendix](Appendix.md)