# 🛡️Potential Malware Activity 
## "DeviceSupport.exe"

## Detail panel for INC-2026-0005
![image alt](https://github.com/Akanksha-cloudsec/incident-alert-document/blob/8628a9dc67f025512cfee7da91092ae9a6955f9b/Report%201/img%201.png)
- Priority score: **500**
- Severity: **Medium**
- Source: **WinEventLog:Microsoft-Windows-Sysmon/Operational**, meaning the detection came from Sysmon (Windows System Monitor) endpoint telemetry.
- Summary: Endpoint telemetry detected activity involving **DeviceSupport.exe** on the machine **NEX-NYC-LT-001**.
- Tags: “Under investigation” and **T1204.002** · **Malicious File**, a **MITRE ATT&CK** technique ID for User Execution: Malicious File, where a user is tricked into running a malicious file.
- Assets involved (2): the endpoint **NEX-NYC-LT-001** (a New York laptop) and the user account **aisha.khan**.
- **I assigned this alert to me**.

---
![image alt](https://github.com/Akanksha-cloudsec/incident-alert-document/blob/1e8414ccf276bd65277ac311cab1eafd5d8c7bc2/Report%201/img%202.png)
- This is the full **Incident Ticket** view for **INC-2026-0005**.
- **Ticket fields**

| **Field** | **Value** |
| :--- | :--- |
| Ticket number | INC-2026-0005 |
| Opened | Oct 3, 12:40 PM · 07:10 UTC |
| Classification | Under investigation |
| Severity | Medium |
| Category | Incident Response |
| Assignment group| SOC Tier-2 |
| Assigned to | Akanksha |
| Asset | NEX-NYC-LT-001 |
| Reported by | SOC Detection Engine |

---

- What full path was recorded for "DeviceSupport.exe".

![image alt](https://github.com/Akanksha-cloudsec/incident-alert-document/blob/1e8414ccf276bd65277ac311cab1eafd5d8c7bc2/Report%201/img%203.png)

**Query**
```bash
index=nexoratech source="WinEventLog:Microsoft-Windows-Sysmon/Operational" "DeviceSupport.exe" host="NEX-NYC-LT-001"
```

What stands out
Execution from Downloads. A binary running out of a user’s Downloads folder, rather than Program Files, is a classic sign of a file the user fetched and ran manually. That fits T1204.002.
Masquerading as HP support. The process is querying support.hp.com, which makes it look like a legitimate HP support tool. That could be a genuine HP utility, or malware borrowing a trusted domain to blend in.
The DNS answer is a private IP, which is the most suspicious part. support.hp.com is a public domain and should resolve to a public IP. It resolved to 10.30.40.25, an RFC 1918 internal address.


