
# Appendix

## Content of Appendix

- [Appendix](#appendix)
  - [Content of Appendix](#content-of-appendix)
  - [Script](#script)
    - [Apply/Update All Policies Script](#applyupdate-all-policies-script)
    - [KubeArmor log Script](#kubearmor-log-script)
    - [Check KubeArmor whitelist category Script](#check-kubearmor-whitelist-category-script)
    - [Hardening policy and test results for product security level](#hardening-policy-and-test-results-for-product-security-level)
    - [Write in etc directory](#write-in-etc-directory)
    - [Remote file copy](#remote-file-copy)
    - [System owner discovery](#system-owner-discovery)
    - [File integrity monitoring](#file-integrity-monitoring)
    - [Write in shm directory](#write-in-shm-directory)
    - [Shell history modification](#shell-history-modification)
    - [Impair defence](#impair-defence)
    - [Package manager execution](#package-manager-execution)
    - [Remote services](#remote-services)
    - [Audit network service scanning](#audit-network-service-scanning)
    - [Audit write under dev directory](#audit-write-under-dev-directory)
    - [Experiment about relationnship between actions](#experiment-about-relationnship-between-actions)
    - [More experiment based on `Block` policy](#more-experiment-based-on-block-policy)
      - [A new `Allow` policy](#a-new-allow-policy)
      - [Inside the `Block` policy](#inside-the-block-policy)
      - [Decision](#decision)


## Script

### Apply/Update All Policies Script

`scripts/apply-policy.sh`

```
#!/bin/sh
kubectl delete --all KubeArmorPolicy -n trirematics

# Define a function to loop through directories recursively
apply_policy() {
    directory="$1"

    # Loop through each item in the directory
    for item in "$directory"/*; do
        # Check if the item is a file
        if [ -f "$item" ]; then
            # Print the file name
            kubectl apply -f "$item"
        elif [ -d "$item" ] && [ "$(basename "$item")" != "." ] && [ "$(basename "$item")" != ".." ]; then
            # If the item is a directory and not . or .., recursively call the function
            apply_policy "$item"
        fi
    done
}

# Provide the directory to start the loop
# start_directory="../KubeArmorPolicy/product"

start_directory=../KubeArmorPolicy/product
# Call the function with the starting directory
apply_policy "$start_directory"

```

### KubeArmor log Script

`KubeArmorPolicy/log/log.sh`

```
# This is script to print the KubeArmor log
rm ./karmor-log.txt
karmor logs --json --logPath ./karmor-log.txt
```

### Check KubeArmor whitelist category Script

`KubeArmorPolicy/log/check_for_keyword.py`

```
# This is a script to check whitelist belong to which section
def check_for_keywords(file_path, keyword_a, cn_keyword, ran_keyword, ue_keyword):
    ue = False
    cn = False
    ran = False
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if keyword_a in line and ue_keyword in line:
                    ue = True
                if keyword_a in line and ran_keyword in line:
                    ran = True
                if keyword_a in line and cn_keyword in line:
                    cn = True
        print(f"UE? '{ue}' CN? '{cn}' RAN? '{ran}' ")
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

file_path = "./karmor-log.txt"  # Replace with your file path
keyword_a = "\"Resource\":\"/opt/hydra/bin/chmod"
cn_keyword = "oai-cn"
ue_keyword = "oai-ue"
ran_keyword = "oai-ran"


check_for_keywords(file_path, keyword_a, cn_keyword, ran_keyword, ue_keyword)
```

### Hardening policy and test results for product security level

### Write in etc directory

Policy: [write-etc-dir](KubeArmorPolicy/product/write-etc-dir/)

Result:
```
kubectl exec -it oai-upf.core.eurecom-6f9b859fb5-cht27  -n trirematics -- bash
root@oai-upf:/# cd /etc/
root@oai-upf:/etc# ls
adduser.conf            cron.daily      environment  hosts        ld.so.conf     machine-id     pam.conf   rc2.d        rmt       subuid         xattr.conf
alternatives            debconf.conf    fstab        hydra        ld.so.conf.d   magma          pam.d      rc3.d        security  sysctl.conf
apt                     debian_version  gai.conf     init.d       legal          mke2fs.conf    passwd     rc4.d        selinux   sysctl.d
bash.bashrc             default         group        issue        libaudit.conf  networks       profile    rc5.d        shadow    systemd
bindresvport.blacklist  deluser.conf    gshadow      issue.net    login.defs     nsswitch.conf  profile.d  rc6.d        shells    t9s
cloud                   dpkg            host.conf    kernel       logrotate.d    opt            rc0.d      rcS.d        skel      terminfo
cron.d                  e2scrub.conf    hostname     ld.so.cache  lsb-release    os-release     rc1.d      resolv.conf  subgid    update-motd.d
root@oai-upf:/etc# touch test
touch: cannot touch 'test': Permission denied
root@oai-upf:/etc# cd t9s/
root@oai-upf:/etc/t9s# cd athena/
root@oai-upf:/etc/t9s/athena# ls
wmi
root@oai-upf:/etc/t9s/athena# touch test
touch: cannot touch 'test': Permission denied
root@oai-upf:/etc/t9s/athena# cd wmi/
root@oai-upf:/etc/t9s/athena/wmi# touch test
root@oai-upf:/etc/t9s/athena/wmi# rm test
root@oai-upf:/etc/t9s/athena/wmi# 
```

### Remote file copy

Policy: [remote-file-copy](KubeArmorPolicy/product/remote-file-copy/)

Result:
```
kubectl exec -it oai-upf.core.eurecom-6f9b859fb5-fpqsj -n trirematics  -- bash
root@oai-upf:/# scp
bash: scp: command not found
root@oai-upf:/# rsync
bash: /opt/hydra/usr/bin/rsync: Permission denied
```

### System owner discovery

Policy: [system-owner-discovery](KubeArmorPolicy/product/system-owner-discovery/)

Result:

```
 kubectl exec -it oai-amf.core.eurecom-c69f45c8f-sr9km -n trirematics -- bash
root@oai-amf:/# id
uid=0(root) gid=0(root) groups=0(root)
root@oai-amf:/# /user/bin/id
bash: /user/bin/id: No such file or directory
root@oai-amf:/# /opt/hydra/usr/bin/id
uid=0(root) gid=0(root) groups=0(root)
root@oai-amf:/# /opt/hydra/usr/bin/whoami
bash: /opt/hydra/usr/bin/whoami: Permission denied
root@oai-amf:/# /opt/hydra/usr/bin/who
bash: /opt/hydra/usr/bin/who: Permission denied
root@oai-amf:/# /usr/bin/w.procps
bash: /usr/bin/w.procps: Permission denied
root@oai-amf:/# whereis bash
bash: /usr/bin/bash /etc/bash.bashrc /opt/hydra/bin/bash
root@oai-amf:/# /usr/bin/bash /opt/hydra/usr/bin/id
/opt/hydra/usr/bin/id: /opt/hydra/usr/bin/id: cannot execute binary file
root@oai-amf:/# ^C
root@oai-amf:/# exit
command terminated with exit code 130

bubbleran@edo:~$ kubectl exec -it oai-amf.core.eurecom-c69f45c8f-sr9km -n trirematics -- /usr/bin/bash
root@oai-amf:/# ^C
root@oai-amf:/# /opt/hydra/usr/bin/id
bash: /opt/hydra/usr/bin/id: Permission denied
root@oai-amf:/# 

```

### File integrity monitoring

Policy: [file-integrity-monitoring](KubeArmorPolicy/product/file-integrity-monitoring/)

Result:
```
kubectl exec -it oai-gnb.test.eurecom-754cf9bf49-n8tz9 -n trirematics -- bash 
root@oai-gnb:/# oai-gnb.test.eurecom-754cf9bf49-n8tz9^C
root@oai-gnb:/# cd /usr/lib/
root@oai-gnb:/usr/lib# ls
apt  dpkg  init  locale  lsb  mime  os-release  sysctl.d  systemd  terminfo  tmpfiles.d  udev  x86_64-linux-gnu
root@oai-gnb:/usr/lib# touch test
touch: cannot touch 'test': Permission denied
root@oai-gnb:/usr/lib# 
```

### Write in shm directory

Policy: [write-in-shm-dir](KubeArmorPolicy/product/write-in-shm-dir/)

Result:
```
kubectl exec -it oai-upf.core.eurecom-6f9b859fb5-f6kw5 -n trirematics  -- bash
root@oai-upf:/# cd /dev/shm/
root@oai-upf:/dev/shm# ls
root@oai-upf:/dev/shm# touch test
touch: cannot touch 'test': Permission denied
root@oai-upf:/dev/shm# 
```

### Shell history modification

Policy: [shell-history-mod](KubeArmorPolicy/product/shell-history-mod/)

Result:

```
kubectl exec -it oai-amf.core.eurecom-c69f45c8f-99drc -n trirematics -- bash
root@oai-amf:/# cat /root/.bash_history 
cat: /root/.bash_history: Permission denied
root@oai-amf:/# rm /root/.bash_history 
rm: cannot remove '/root/.bash_history': Permission denied
root@oai-amf:/# mv /root/.bash_history test
mv: cannot move '/root/.bash_history' to 'test': Permission denied
root@oai-amf:/# 
```

### Impair defence

Policy: [impair-defense](KubeArmorPolicy/product/impair-defense/)

Result:
```
 kubectl exec -it oai-upf.core.eurecom-6f9b859fb5-7tt9r -n trirematics -- bash
root@oai-upf:/# cd /etc/selinux/
root@oai-upf:/etc/selinux# ls
ls: cannot open directory '.': Permission denied
root@oai-upf:/etc/selinux# cd /etc/sysconfig/selinux/
bash: cd: /etc/sysconfig/selinux/: No such file or directory
root@oai-upf:/etc/selinux# cd /etc/apparmor.d/
bash: cd: /etc/apparmor.d/: No such file or directory
root@oai-upf:/etc/selinux# 
```

### Package manager execution

Policy: [pkg-mngr-exec](KubeArmorPolicy/product/pkg-mngr-exec/)

Result:
```
kubectl exec -it oai-smf.core.eurecom-7d67695f9b-6d9vf -n trirematics -- bash
root@oai-smf:/# apt update
bash: /usr/bin/apt: Permission denied
root@oai-smf:/# apt-get install
bash: /usr/bin/apt-get: Permission denied
root@oai-smf:/#
```

### Remote services

Policy: [remote-services](KubeArmorPolicy/product/remote-services/)

Result:
```
kubectl exec -it oai-gnb.test.eurecom-754cf9bf49-z8l4f -n trirematics  -- bash
root@oai-gnb:/# cat /etc/shadow
cat: /etc/shadow: Permission denied
root@oai-gnb:/# cat /var/log/wtmp
cat: /var/log/wtmp: Permission denied
```

### Audit network service scanning

Policy: [audit-network-service-scanning](KubeArmorPolicy/product/audit-network-service-scanning.yaml)

Result:
```
{
  "Timestamp": 1707423876,
  "UpdatedTime": "2024-02-08T20:24:36.482577Z",
  "ClusterName": "default",
  "HostName": "edo",
  "NamespaceName": "trirematics",
  "Owner": {
    "Ref": "Deployment",
    "Name": "oai-smf.core.eurecom",
    "Namespace": "trirematics"
  },
  "PodName": "oai-smf.core.eurecom-7d67695f9b-hhj4h",
  "Labels": "app.kubernetes.io/version=v4.1.0-v1.5.1,app.kubernetes.io/name=smf,app.kubernetes.io/created-by=athena-base-operator,app.kubernetes.io/managed-by=athena-base-operator,app.kubernetes.io/part-of=core.eurecom,roles.athena.t9s.io/smf=active,athena.t9s.io/network=core.eurecom,app.kubernetes.io/component=oai-smf,app.kubernetes.io/instance=TODO,athena.t9s.io/element-name=oai-smf.core.eurecom",
  "ContainerID": "7be800950f5c356f61472224bbd770d927852c6ad1917248d2f925c642f6ad3e",
  "ContainerName": "smf",
  "ContainerImage": "hub.bubbleran.com/oai/oai-cn:v4.1.0-v1.5.1@sha256:37d5a7904727f833e1563c830d1b28d7780b73f327b3f915baf159863d3d96ff",
  "HostPPID": 2084981,
  "HostPID": 2086462,
  "PPID": 1245,
  "PID": 1255,
  "UID": 0,
  "ParentProcessName": "/opt/hydra/bin/bash",
  "ProcessName": "/opt/hydra/bin/ip",
  "PolicyName": "audit-network-service-scanning",
  "Severity": "5",
  "Tags": "MITRE,FGT1046,FIGHT",
  "ATags": [
    "MITRE",
    "FGT1046",
    "FIGHT"
  ],
  "Message": "Network service has been scanned!",
  "Type": "MatchedPolicy",
  "Source": "/opt/hydra/bin/bash",
  "Operation": "Process",
  "Resource": "/opt/hydra/bin/ip -V",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "eBPF Monitor",
  "Action": "Audit",
  "Result": "Passed"
}

```

### Audit write under dev directory


Policy: [audit-write-under-dev-dir](KubeArmorPolicy/product/audit-write-under-dev-dir.yaml)

Result:
```
{
  "Timestamp": 1708493056,
  "UpdatedTime": "2024-02-21T05:24:16.442240Z",
  "ClusterName": "default",
  "HostName": "edo",
  "NamespaceName": "trirematics",
  "Owner": {
    "Ref": "Deployment",
    "Name": "oai-upf.core.eurecom",
    "Namespace": "trirematics"
  },
  "PodName": "oai-upf.core.eurecom-6f9b859fb5-fpqsj",
  "Labels": "athena.t9s.io/element-name=oai-upf.core.eurecom,app.kubernetes.io/component=oai-upf,app.kubernetes.io/name=spgwu,athena.t9s.io/network=core.eurecom,app.kubernetes.io/version=v4.1.0-v1.5.1,roles.athena.t9s.io/upf=active,app.kubernetes.io/created-by=athena-base-operator,roles.athena.t9s.io/spgwu=active,app.kubernetes.io/instance=TODO,app.kubernetes.io/part-of=core.eurecom,app.kubernetes.io/managed-by=athena-base-operator",
  "ContainerID": "d2322d8d8682b652b61cbc0ea2f738f2630037dc2a349811f44e1c611dc806b8",
  "ContainerName": "upf",
  "ContainerImage": "hub.bubbleran.com/oai/oai-cn:v4.1.0-v1.5.1@sha256:37d5a7904727f833e1563c830d1b28d7780b73f327b3f915baf159863d3d96ff",
  "HostPPID": 1196287,
  "HostPID": 1197259,
  "PPID": 1283,
  "PID": 1291,
  "UID": 0,
  "ProcessName": "/opt/hydra/bin/touch",
  "PolicyName": "DefaultPosture",
  "Type": "MatchedPolicy",
  "Source": "/opt/hydra/bin/touch test",
  "Operation": "File",
  "Resource": "/dev/test",
  "Data": "lsm=FILE_OPEN",
  "Enforcer": "BPFLSM",
  "Action": "Audit",
  "Result": "Passed",
  "Cwd": "/"
}

```

### Experiment about relationnship between actions

Step:

1. Turn on the log monitor to get the latest log from KubeArmor.
2. Change one of the Policy: block-write-etc-dir.

**Action from 'Audit' to 'Allow' (whitelist mode)**

Expected:

- 5G network cluster works
- show Allow logs

**Result**: No related log for designed rules. However, the network was installed normally and worked properly.

**Analysis**: For `Allow` policy, it will not generate log.

**Action from 'Audit' to 'Block' (blacklist)**.

Expected:

- 5G network cluster cannot work
- show Block logs

**Result**: It shows in the log, and the network cannot install.


### More experiment based on `Block` policy

What if the `Block` policy includes a small `Allow` policy, e.g., for the whole directory, there is only one folder or file allowed to access.

`Allow` policy

```
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: allow-write-specific-dir
  namespace: trirematics
spec:
  severity: 3
  message: Specific directory was accessed
  tags:
  - ALLOW
  message: Allow by specific rule
  action:
    Allow
  selector:
    matchLabels:
      app.kubernetes.io/created-by: athena-base-operator
      app.kubernetes.io/managed-by: athena-base-operator
  file:
    matchPaths:
    - path: /etc/ld.so.cache
      action: Allow
```

`Block` policy

```
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: block-write-etc-dir
  namespace: trirematics
spec:
  action: Block
  file:
    matchDirectories:
    - dir: /etc/
      readOnly: true
      recursive: true
    - dir: /etc/t9s/athena/
      recursive: true
      fromSource:
      - path: /usr/bin/bash
      - path: /opt/hydra/bin/bash
      - path: /etc/bash.bashrc
      - path: /etc/bash
    matchPaths:
    - path: /etc/ld.so.cache
    - path: /etc/nsswitch.conf
      action: Allow
  message: Alert! File creation under /etc/ directory detected.
  selector:
    matchLabels:
      app.kubernetes.io/created-by: athena-base-operator
      app.kubernetes.io/managed-by: athena-base-operator
  severity: 5
  tags:
  - NIST_800-53_SI-7
  - NIST
  - NIST_800-53_SI-4
  - NIST_800-53
  - MITRE_T1562.001_disable_or_modify_tools
  - MITRE_T1036.005_match_legitimate_name_or_location
  - MITRE_TA0003_persistence
  - MITRE
  - MITRE_T1036_masquerading
  - MITRE_TA0005_defense_evasion

```
There are two possibilities for a `Allow` policy: inside the `Block` policy or a new `Allow` policy

#### A new `Allow` policy

```
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: allow-write-specific-dir
  namespace: trirematics
spec:
  severity: 3
  message: Specific directory was accessed
  tags:
  - ALLOW
  message: Allow by specific rule
  action:
    Allow
  selector:
    matchLabels:
      app.kubernetes.io/created-by: athena-base-operator
      app.kubernetes.io/managed-by: athena-base-operator
  process:
    matchDirectories:
    - dir: /sys/devices/
      recursive: true
  file:
    matchPaths:
    - path: /etc/ld.so.cache
      action: Allow
    - path: /etc/nsswitch.conf
      action: Allow
    - path: /etc/t9s/athena/wmi/logs
      action: Allow
```

This policy's log disappeared.
Analysis: It works, but it didn't print the log of allow, and the other block's policy becomes DefaultPosture.


#### Inside the `Block` policy

```
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: block-write-etc-dir
  namespace: trirematics
spec:
  action: Block
  file:
    matchDirectories:
    - dir: /etc/
      readOnly: true
      recursive: true
    - dir: /etc/t9s/athena/
      recursive: true
      fromSource:
      - path: /usr/bin/bash
      - path: /opt/hydra/bin/bash
      - path: /etc/bash.bashrc
      - path: /etc/bash
    matchPaths:
    - path: /etc/ld.so.cache
      action: Allow
    - path: /etc/nsswitch.conf
      action: Allow
  message: Alert! File creation under /etc/ directory detected.
  selector:
    matchLabels:
      app.kubernetes.io/created-by: athena-base-operator
      app.kubernetes.io/managed-by: athena-base-operator
  severity: 5
  tags:
  - NIST_800-53_SI-7
  - NIST
  - NIST_800-53_SI-4
  - NIST_800-53
  - MITRE_T1562.001_disable_or_modify_tools
  - MITRE_T1036.005_match_legitimate_name_or_location
  - MITRE_TA0003_persistence
  - MITRE
  - MITRE_T1036_masquerading
  - MITRE_TA0005_defense_evasion

```

**Result:** the `Allow` policy's log disappears, but it shows the other `Block` policies' log.

However, If I set two small `Allow` policies inside, it only allowed the first policy, and block the second one.

**Analysis:** The `Block` policy only executes one `Allow` policy inside itself.

#### Decision

Used `Allow` and `Block` policy at the same time

First, use the `Block` policy on the big range of directories, and then check the log to complete the `Allow` policy (The one needed for the installation and test). Each time, I will go into the pod and then run the related, and then run the ping test to see if everything is good.
