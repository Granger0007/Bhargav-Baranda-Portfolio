# Lab 003: Subnetting Fundamentals - Dividing Networks Without Calculators

## Lab Overview

| Field | Details |
|-------|---------|
| **Lab ID** | 003 |
| **Date Completed** | February 2026 |
| **Lab Type** | Network Fundamentals - Subnetting |
| **Method** | Mental arithmetic (no calculator) |
| **Objective** | Divide /24 network into four equal /26 subnets |
| **Skill Focus** | Network segmentation, IP addressing, subnet boundary identification |

---

## Executive Summary

Successfully divided a Class C network (192.168.1.0/24) into four equal subnets (/26) using mental arithmetic only. This exercise demonstrates the fundamental network architecture knowledge required for SOC analysts to identify subnet boundaries during incident investigation, particularly when detecting lateral movement attacks. The lab reinforces Security+ Objective 3.3 (secure network architecture) and provides the speed-of-thought IP address analysis needed during active security incidents.

**Key Accomplishment:**
- Calculated four /26 subnets from /24 network without tools
- Identified all network addresses, broadcast addresses, and usable host ranges
- Applied knowledge to lateral movement detection scenario
- Demonstrated subnet boundary crossing identification

---

## Why Subnetting Matters in Security Operations

### Real-World SOC Application

When a security alert fires in a corporate monitoring system, it includes an IP address identifying the device involved. A SOC analyst must instantly determine:

- **Which network segment** does this device belong to?
- **Which department/building/security zone** is it in?
- **Which firewall rules** apply to this traffic?
- **Should this device** be communicating with the destination?

All of these answers flow from understanding subnet boundaries.

### Lateral Movement Detection

**Attack Pattern:** After compromising one computer, attackers move sideways through the network (lateral movement), jumping from machine to machine to reach valuable targets.

**Detection Method:** Lateral movement almost always involves crossing subnet boundaries. An analyst who can read those boundaries in real-time identifies the attack while it's happening.

**Example Alert:**
```
"Suspicious traffic detected: 192.168.1.147 → 192.168.1.200"
```

**Instant Analysis (No Calculator):**
- 192.168.1.147 → Subnet 3 (128-191 range)
- 192.168.1.200 → Subnet 4 (192-255 range)
- **Finding:** Traffic crossing subnet boundary
- **Action:** Check firewall logs for authorization
- **If unauthorized:** Potential lateral movement - escalate immediately

---

## IP Addressing Fundamentals

### What is an IP Address?

Every device on a network has an IP address:
```
192.168.1.0
```

**Structure:**
- Four numbers (octets) separated by dots
- Each octet represents 8 bits of binary
- Total: 32 bits
- Each octet range: 0-255

### Understanding Prefix Length (/24)

The "/24" notation indicates how many bits identify the network versus individual devices:
```
/24 = 24 bits for network identification
      32 - 24 = 8 bits for host addresses
      2⁸ = 256 possible addresses
```

**A /24 network contains exactly 256 IP addresses**

### Reserved Addresses

Every subnet has two reserved addresses that cannot be assigned to devices:

**Network Address (First Address):**
- Example: 192.168.1.0
- Purpose: Identifies the network itself
- Analogy: Street sign with the street name

**Broadcast Address (Last Address):**
- Example: 192.168.1.255
- Purpose: Sends messages to all devices simultaneously
- Analogy: Megaphone that reaches every house on the street

**Result:** 256 total - 2 reserved = **254 usable addresses**

---

## The Subnetting Task

### Objective
Divide 192.168.1.0/24 into **four equal subnets** using mental arithmetic only.

### The Four-Step Mental Process

**STEP 1 - Calculate Host Bits:**
```
32 (total bits) - 24 (network bits) = 8 host bits available
```

**STEP 2 - Determine Bits to Borrow:**
```
Need 4 subnets → What power of 2 gives 4?
2² = 4 → Borrow 2 bits from host portion
```

**STEP 3 - Calculate New Prefix:**
```
24 (original) + 2 (borrowed) = /26
All four subnets will be /26 networks
```

**STEP 4 - Calculate Block Size:**
```
6 host bits remaining (8 - 2 = 6)
2⁶ = 64 addresses per subnet
```

**Verification:**
```
4 subnets × 64 addresses = 256 total addresses ✓
Matches original /24 exactly - no overlap, no gaps
```

---

## The Four Subnets - Complete Breakdown

### Subnet 1: 192.168.1.0/26

**Address Range:** 192.168.1.0 - 192.168.1.63

| Function | Address | Notes |
|----------|---------|-------|
| Network Address | 192.168.1.0 | Reserved - cannot assign to device |
| First Usable Host | 192.168.1.1 | First assignable address |
| Last Usable Host | 192.168.1.62 | Last assignable address |
| Broadcast Address | 192.168.1.63 | Reserved - reaches all devices in subnet |
| **Total Usable Hosts** | **62** | Devices that can be assigned addresses |

---

### Subnet 2: 192.168.1.64/26

**Address Range:** 192.168.1.64 - 192.168.1.127

| Function | Address | Notes |
|----------|---------|-------|
| Network Address | 192.168.1.64 | Reserved |
| First Usable Host | 192.168.1.65 | Starts immediately after network address |
| Last Usable Host | 192.168.1.126 | Ends just before broadcast |
| Broadcast Address | 192.168.1.127 | Reserved - only reaches Subnet 2 devices |
| **Total Usable Hosts** | **62** | Same capacity as all /26 subnets |

---

### Subnet 3: 192.168.1.128/26

**Address Range:** 192.168.1.128 - 192.168.1.191

| Function | Address | Notes |
|----------|---------|-------|
| Network Address | 192.168.1.128 | Reserved |
| First Usable Host | 192.168.1.129 | |
| Last Usable Host | 192.168.1.190 | |
| Broadcast Address | 192.168.1.191 | Reserved |
| **Total Usable Hosts** | **62** | Consistent across all subnets |

---

### Subnet 4: 192.168.1.192/26

**Address Range:** 192.168.1.192 - 192.168.1.255

| Function | Address | Notes |
|----------|---------|-------|
| Network Address | 192.168.1.192 | Reserved |
| First Usable Host | 192.168.1.193 | |
| Last Usable Host | 192.168.1.254 | **Always one before .255** |
| Broadcast Address | 192.168.1.255 | Final address of entire /24 range |
| **Total Usable Hosts** | **62** | Same as all other /26 subnets |

**Critical Note:** The last usable host is always **192.168.1.254** - never .256. An octet cannot exceed 255.

---

## Complete Subnet Summary Table

| Subnet | Network Address | First Host | Last Host | Broadcast | Usable Hosts |
|:------:|----------------|------------|-----------|-----------|:------------:|
| 1 /26 | 192.168.1.0 | 192.168.1.1 | 192.168.1.62 | 192.168.1.63 | 62 |
| 2 /26 | 192.168.1.64 | 192.168.1.65 | 192.168.1.126 | 192.168.1.127 | 62 |
| 3 /26 | 192.168.1.128 | 192.168.1.129 | 192.168.1.190 | 192.168.1.191 | 62 |
| 4 /26 | 192.168.1.192 | 192.168.1.193 | 192.168.1.254 | 192.168.1.255 | 62 |

**Verification:** 4 subnets × 64 addresses = 256 addresses total ✓

---

## Subnetting Patterns - Quick Reference

### Common Subnet Masks from /24

| Prefix | Block Size | Usable Hosts | Subnets from /24 | Use Case |
|:------:|:----------:|:------------:|:----------------:|----------|
| /25 | 128 | 126 | 2 | Large departments |
| /26 | 64 | 62 | 4 | **This lab** |
| /27 | 32 | 30 | 8 | Medium teams |
| /28 | 16 | 14 | 16 | Small workgroups |
| /29 | 8 | 6 | 32 | Point-to-point links |
| /30 | 4 | 2 | 64 | Router-to-router connections |

**Pattern Recognition:**
- Each step down: Block size **halves**
- Each step down: Number of subnets **doubles**
- Formula: 2^(32-prefix) = block size

---

## Security Operations Application

### Scenario: Lateral Movement Detection

**Alert Received:**
```
Timestamp: 2026-02-27 03:42:15 UTC
Source: 192.168.1.147
Destination: 192.168.1.200
Protocol: SMB (Port 445)
Action: Connection Established
```

### Instant Analysis (No Calculator Required)

**Step 1 - Identify Source Subnet:**
- 192.168.1.147 falls between 128-191
- **Subnet 3** (192.168.1.128/26)

**Step 2 - Identify Destination Subnet:**
- 192.168.1.200 falls between 192-255
- **Subnet 4** (192.168.1.192/26)

**Step 3 - Security Assessment:**
- Traffic is **crossing subnet boundary** (Subnet 3 → Subnet 4)
- SMB traffic should not cross subnets without firewall authorization
- Check firewall logs for approved cross-subnet SMB traffic

**Step 4 - Investigation Actions:**
1. Query firewall logs for 192.168.1.147 → 192.168.1.200
2. If no authorization found → **Potential lateral movement**
3. Check authentication logs on 192.168.1.200
4. Review recent activity from 192.168.1.147
5. Isolate both endpoints if compromise confirmed

**Total Analysis Time:** < 10 seconds

---

## Common Mistakes and Lessons Learned

### Mistake: Invalid Octet Value

**Error Made:**
Wrote broadcast address as 192.168.0.**256**

**Correction:**
IP address octets range from **0-255** only. The value 256 does not exist in IP addressing.

**Correct Answer:**
Last subnet broadcast: 192.168.0.**255**  
Last usable host: 192.168.0.**254**

**Rule:** The last usable host in any subnet is always (broadcast address - 1)

---

## MITRE ATT&CK Framework Mapping

| Tactic | Technique ID | Technique Name | Subnetting Relevance |
|--------|--------------|----------------|---------------------|
| Lateral Movement | T1021 | Remote Services | Detecting cross-subnet unauthorized connections |
| Discovery | T1018 | Remote System Discovery | Attackers scanning across subnet boundaries |
| Lateral Movement | T1210 | Exploitation of Remote Services | Services exposed across improperly segmented subnets |

**Detection Opportunity:**
Monitoring for traffic crossing subnet boundaries without firewall authorization is a primary method for detecting lateral movement in its early stages.

---

## Security+ Knowledge Connection

**CompTIA Security+ SY0-701 Coverage:**

- **Objective 3.3** - Given a scenario, implement secure network architecture
  - Subnetting and network segmentation
  - VLSM (Variable Length Subnet Masking)
  - Network isolation and microsegmentation

**Exam Question Types:**
- Calculate subnets from given prefix
- Identify valid host ranges
- Determine network/broadcast addresses
- Variable length subnetting scenarios (different sized departments)

**Mental Math Requirement:**
Security+ exam does not allow calculators. Subnetting questions must be solved mentally using the four-step process demonstrated in this lab.

---

## Skills Demonstrated

**Network Fundamentals:**
- IP addressing structure and notation
- CIDR (Classless Inter-Domain Routing) prefix notation
- Binary-to-decimal conversion (conceptual understanding)
- Network segmentation principles

**Mental Arithmetic:**
- Powers of 2 (2¹ through 2⁸)
- Subnet boundary calculation
- Host range identification
- No calculator dependency

**Security Analysis:**
- Subnet boundary identification in real-time
- Lateral movement pattern recognition
- Firewall rule analysis requirements
- Network segmentation security implications

**SOC Analyst Workflow:**
- Rapid IP address classification during incidents
- Subnet-aware alert triage
- Cross-segment traffic analysis
- Network architecture comprehension

---

## Interview Application

**Question:** "How would you investigate a potential lateral movement alert?"

**Answer:**
"First, I'd analyze the source and destination IP addresses to determine if they're in the same subnet or crossing boundaries. For example, if I see traffic from 192.168.1.147 to 192.168.1.200 in a /24 network divided into /26 subnets, I can immediately identify that's Subnet 3 communicating with Subnet 4—a boundary crossing. I'd then check firewall logs to verify if that cross-subnet traffic is authorized. If the firewall has no record of permitting that connection, and especially if it's SMB or RDP traffic, that's a strong indicator of lateral movement. I can do this analysis mentally in under 10 seconds without needing a subnet calculator."

**Why This Answer Works:**
- Specific IP addresses and subnet sizes
- Demonstrates mental calculation ability
- Shows understanding of lateral movement patterns
- References firewall correlation
- Quantifies response time
- Portfolio-backed (this lab proves the skill)

---

## Additional Practice Scenarios

### Scenario 1: Variable Length Subnetting

**Task:** Subnet 192.168.10.0/24 for three departments:
- Engineering: 100 hosts needed
- Sales: 50 hosts needed  
- HR: 25 hosts needed

**Solution:**
- Engineering: 192.168.10.0/25 (126 usable hosts)
- Sales: 192.168.10.128/26 (62 usable hosts)
- HR: 192.168.10.192/27 (30 usable hosts)
- Remaining: 192.168.10.224/27 (available for growth)

---

### Scenario 2: Point-to-Point Links

**Task:** Create 4 router-to-router connections from 10.0.0.0/24

**Solution:** Use /30 subnets (2 usable hosts each)
- Link 1: 10.0.0.0/30 (hosts: .1 and .2)
- Link 2: 10.0.0.4/30 (hosts: .5 and .6)
- Link 3: 10.0.0.8/30 (hosts: .9 and .10)
- Link 4: 10.0.0.12/30 (hosts: .13 and .14)

---

## Key Formulas Reference

**Host Bits:**
```
Host Bits = 32 - Prefix Length
Example: 32 - 24 = 8 host bits
```

**Number of Addresses:**
```
Addresses = 2^Host Bits
Example: 2⁸ = 256 addresses
```

**Usable Hosts:**
```
Usable = Addresses - 2
Example: 256 - 2 = 254 usable
```

**Bits to Borrow:**
```
2^n ≥ Subnets Needed
Example: Need 4 subnets → 2² = 4 → Borrow 2 bits
```

**New Prefix:**
```
New Prefix = Original + Borrowed Bits
Example: 24 + 2 = /26
```

---

## References

- RFC 1878: Variable Length Subnet Table
- RFC 4632: Classless Inter-domain Routing (CIDR)
- CompTIA Security+ Study Guide (SY0-701)
- MITRE ATT&CK Framework: Lateral Movement Techniques

---

**Lab Completed:** February 27, 2026  
**Analyst:** Bhargav Baranda  
**Lab ID:** 003  
**Method:** Mental arithmetic (no calculator)  
**Result:** Four /26 subnets calculated and verified ✓
