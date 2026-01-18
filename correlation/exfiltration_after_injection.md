# Correlation Rule: Process Injection Followed by Exfiltration

## Description
This correlation rule detects hosts that first exhibit **process injection behavior** and then perform **suspicious outbound data exfiltration** within a short time window.

This pattern strongly indicates active malware execution rather than benign software behavior.

---

## Logic

1. Endpoint generates alert for:
   - RWX memory allocation
   - Process access with high privileges

2. Same host generates alert for:
   - Large HTTP POST request
   - Suspicious PHP endpoint
   - High outbound data volume

3. Both events occur within **10 minutes**

---

## Pseudo Logic

IF
  EndpointAlert == RWX_Memory
AND
  NetworkAlert == HTTP_Exfiltration
AND
  TimeDiff <= 10 minutes
THEN
  Raise High Severity Incident

---

## MITRE Mapping

- T1055 – Process Injection
- T1041 – Exfiltration Over C2 Channel

---

## SOC Response Actions

- Isolate host
- Capture memory
- Block destination domain
- Reset user credentials
- Perform full disk scan

---

## Severity
**High**
