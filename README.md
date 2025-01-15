# THM-Writeup-SigHunt
Writeup for TryHackMe SigHunt Lab - Sigma rules repository for advanced threat detection, detecting malicious IoCs, including HTA payloads, certutil abuse, and ransomware activity on Windows.


### **Challenge 1: HTA Payload Detection**

**Scenario**: The attacker executed an HTA file using `mshta.exe`, with `chrome.exe` as the parent process.

**Steps Taken**:
1. I analyzed the IoCs provided: 
   - Parent process (`chrome.exe`) initiating `mshta.exe`.
   - A command-line execution pointing to an HTA file.

2. I crafted a Sigma rule targeting process creation (`EventID: 1`) to detect this behavior:
   ```yaml
   detection:
     selection:
       EventID: 1
       ParentImage|endswith: 'chrome.exe'
       Image|endswith: 'mshta.exe'
     condition: selection
   ```

**Explanation**:
- **Why EventID 1**: This event logs process creation, crucial for tracing parent-child relationships.
- **Behavioral Focus**: Identifying `chrome.exe` as the parent process ensures this rule targets phishing activity rather than benign HTA usage.
- **IoC Precision**: Restricting the rule to `mshta.exe` avoids noise while effectively flagging the execution of potentially malicious HTML applications.

**Flag**: `THM{ph1sh1ng_msht4_101}`

---

### **Challenge 2: Certutil Download**

**Scenario**: The attacker used `certutil.exe` to download a malicious payload.

**Steps Taken**:
1. I reviewed the IoCs, which included:
   - Use of `certutil.exe`.
   - Command-line arguments: `-urlcache`, `-split`, and `-f`.

2. I created the following Sigma rule:
   ```yaml
   detection:
     selection:
       EventID: 1
       Image|endswith: 'certutil.exe'
       CommandLine|contains|all:
         - 'certutil'
         - '-urlcache'
         - '-split'
         - '-f'
     condition: selection
   ```

**Explanation**:
- **Why Certutil**: As a trusted utility, it is frequently abused by attackers to download payloads while bypassing defenses.
- **Command-Line Focus**: Targeting specific arguments ensures detection of download-related misuse without flagging legitimate certificate management tasks.

**Flag**: `THM{n0t_just_4_c3rts}`

---

### **Challenge 3: Netcat Reverse Shell**

**Scenario**: A reverse shell was established using `nc.exe`.

**Steps Taken**:
1. I identified two IoCs:
   - The presence of `nc.exe` in process creation.
   - A specific MD5 hash for the file.

2. I crafted a Sigma rule to detect both the executable and its hash:
   ```yaml
   detection:
     selection1:
       EventID: 1
       Image|endswith: 'nc.exe'
       CommandLine|contains|all:
         - ' -e '
     selection2:
       Hashes|contains: '523613A7B9DFA398CBD5EBD2DD0F4F38'
     condition: selection1 or selection2
   ```

**Explanation**:
- **Dual Detection**: Including the hash ensures coverage if the filename is obfuscated or altered.
- **Command-Line Arguments**: The `-e` switch indicates an attempt to spawn a shell, a strong indicator of malicious activity.

**Flag**: `THM{cl4ss1c_n3tc4t_r3vs}`

---

### **Challenge 4: PowerUp Enumeration**

**Scenario**: The attacker ran the `PowerUp` script via PowerShell.

**Steps Taken**:
1. I analyzed the PowerShell command-line:
   - The script invoked `Invoke-AllChecks`.
   - The `PowerUp` enumeration tool was explicitly mentioned.

2. I created this Sigma rule:
   ```yaml
   detection:
     selection:
       EventID: 1
       Image|endswith: 'powershell.exe'
       CommandLine|contains|all:
         - 'Invoke-AllChecks'
         - 'PowerUp'
     condition: selection
   ```

**Explanation**:
- **Why Command-Line Analysis**: PowerShell abuse often involves explicit commands that can be precisely detected.
- **Targeted Keywords**: Detecting `Invoke-AllChecks` and `PowerUp` ensures the rule focuses on privilege escalation attempts.

**Flag**: `THM{p0wp0wp0w3rup_3num}`

---

### **Challenge 5: Service Binary Modification**

**Scenario**: A service was modified using `sc.exe`.

**Steps Taken**:
1. I reviewed the IoCs:
   - Use of `sc.exe` with `config` and `binPath=` in the command line.

2. The resulting Sigma rule was:
   ```yaml
   detection:
     selection:
       EventID: 1
       Image|endswith: 'sc.exe'
       CommandLine|contains|all:
         - 'sc.exe'
         - 'config'
         - 'binPath='
     condition: selection
   ```

**Explanation**:
- **Service Misuse**: Modifying `binPath` is a known persistence mechanism.
- **Specificity**: Targeting the command structure avoids unnecessary alerts while effectively detecting malicious activity.

**Flag**: `THM{ov3rpr1v1l3g3d_s3rv1c3}`

---

### **Challenge 6: RunOnce Persistence**

**Scenario**: The attacker leveraged the `RunOnce` registry key for persistence.

**Steps Taken**:
1. I targeted the registry modification with specific keywords:
   - `RunOnce`, `add`, and `reg.exe`.

2. My Sigma rule was:
   ```yaml
   detection:
     selection:
       EventID: 1
       Image|endswith: 'reg.exe'
       CommandLine|contains|all:
         - 'RunOnce'
         - 'add'
     condition: selection
   ```

**Explanation**:
- **Registry Focus**: The `RunOnce` key is a common persistence vector.
- **Why EventID 1**: Detecting the `reg.exe` process ensures we identify the modification at execution time.

**Flag**: `THM{h1d3_m3_1n_run0nc3}`

---

### **Lessons Learned**

1. **Precision Is Key**:
   - Overly broad rules can flood analysts with false positives. Focusing on exact IoCs ensures meaningful alerts.

2. **Behavioral Analysis**:
   - Understanding attacker behaviors (e.g., abuse of trusted binaries) enables the creation of targeted detection mechanisms.

3. **Dual-Method Detection**:
   - Combining filename and hash-based detection ensures resilience against basic obfuscation techniques.

4. **Operational Context**:
   - Each rule should consider the operational environment to avoid interference with legitimate activities.

