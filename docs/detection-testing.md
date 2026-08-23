# Detection Testing & Tuning

## Overview

Custom Wazuh detections were tested against multiple execution methods and command variations to identify false negatives, detection gaps, and potential false positives.

The testing process followed an iterative workflow:

**Create Detection → Generate Activity → Validate Alert → Test Bypass → Tune Detection → Retest**

---

## Rule 100102 — Windows Account Discovery

**MITRE ATT&CK:** T1087 — Account Discovery

### Testing Results

| Test | Expected | Result |
|---|---|---|
| `net user` from PowerShell | Alert | ✅ Alert |
| `net user` from Command Prompt | Alert | ✅ Alert after tuning |
| `net.exe user` | Alert | ✅ Alert |
| `net1.exe user` | Alert | ✅ Alert after tuning |
| `NET USER` | Alert | ✅ Alert |
| `net1.exe USER` | Alert | ✅ Alert |
| `net user administrator` | Alert | ✅ Alert |
| `net start` | No Alert | ✅ No Alert |

### Detection Gap — Parent Process

The original detection required `powershell.exe` as the parent process.

Executing:

```cmd
net user
```

from Command Prompt resulted in no alert.

The underlying account discovery behavior was the same, but changing the execution shell bypassed the detection.

### Tuning

The PowerShell parent-process requirement was removed.

The detection was changed to focus on the underlying behavior rather than the shell used to execute it.

Retesting confirmed that account discovery was successfully detected from both PowerShell and Command Prompt.

### Detection Gap — net1.exe

The original rule matched:

```text
net.exe
```

Testing showed that:

```cmd
net1.exe user
```

performed similar account discovery without triggering the original rule.

The image-matching expression was updated from:

```regex
(?i)\\net\.exe$
```

to:

```regex
(?i)\\net1?\.exe$
```

This allows the detection to match both `net.exe` and `net1.exe`.

---

## Rule 100103 — Privileged Group Discovery

**MITRE ATT&CK:** T1069.001 — Permission Groups Discovery: Local Groups

### Testing Results

| Test | Expected | Result |
|---|---|---|
| `net localgroup administrators` from PowerShell | Alert | ✅ Alert |
| `net localgroup administrators` from CMD | Alert | ✅ Alert after tuning |
| `net.exe localgroup administrators` | Alert | ✅ Alert |
| `net1.exe localgroup administrators` | Alert | ✅ Alert after tuning |
| `NET LOCALGROUP ADMINISTRATORS` | Alert | ✅ Alert |

Rule 100103 underwent similar tuning to remove unnecessary dependence on PowerShell and to support both `net.exe` and `net1.exe`.

---

## Negative Testing

Negative testing was performed to determine whether the account discovery rule generated alerts for unrelated `net.exe` activity.

The following command was tested:

```cmd
net start
```

**Result:** No Rule 100102 alert was generated.

This confirmed that the detection was not simply triggering on every execution of `net.exe`.

---

## Lessons Learned

Testing demonstrated that a detection successfully generating an alert does not necessarily mean the detection provides sufficient coverage.

The initial detections worked under expected conditions but testing identified multiple gaps:

- Dependence on a specific parent process
- Dependence on `net.exe`
- Alternate execution through `net1.exe`
- Command case variations
- Potential false-positive considerations

Iterative testing and tuning improved the detections by focusing on the underlying discovery behavior rather than a single execution method.
