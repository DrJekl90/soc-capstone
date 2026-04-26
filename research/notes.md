# Research Notes

## Identity Attack Landscape

Cloud identity is the new perimeter. Most breaches I looked at during research started
with compromised credentials or session tokens, not network exploitation. Azure AD is
the authentication backbone for most M365 tenants, which makes its sign-in and audit
logs the most valuable telemetry source for identity-based detection.

## Impossible Travel

The concept is straightforward: if a user authenticates from two cities that are
physically impossible to travel between in the elapsed time, something is wrong.
The tricky part is setting the speed threshold. Commercial flights hit around 900 km/h,
so I set the baseline at 800 km/h to avoid flagging legitimate air travel. VPN usage
can cause false positives because corporate VPN egress points in different countries
will trigger this rule. Tuning requires a baseline of normal user travel patterns.

## MFA Fatigue

This became prominent after the Uber breach in 2022. The attacker hammers the target
with push notifications until they approve one out of frustration or confusion. Azure AD
logs this as repeated 500121 errors followed by a success. The detection window matters.
I found 15 minutes with a threshold of 5 failures catches real attacks without too much
noise. Number-matching MFA largely mitigates this, but not every tenant has it turned on.

## Token Replay

Stolen tokens bypass MFA entirely because the authentication already happened. The key
indicator is the same token (tracked via CorrelationId) appearing from a different IP,
device OS, or browser than the original session. The challenge is that Azure AD does not
always populate deviceId, so I had to broaden the correlation to include OS and browser
fingerprinting. Microsoft's token protection (Proof of Possession) addresses this at the
protocol level, but adoption is still in early stages.

## OAuth Consent Phishing

Attackers register a malicious app (often impersonating a known brand like DocuSign or
Adobe) and send consent links to users. When the user grants consent, the app gets
persistent API access to their mailbox and files with no password theft needed. The
detection focuses on AuditLogs where the consent event includes sensitive scopes like
Mail.ReadWrite or Files.ReadWrite.All. The strongest signal is multiple users consenting
to the same unfamiliar app in a short window, which points to a phishing campaign rather
than legitimate app adoption.

## Password Spraying

Spray attacks are different from brute force in an important way: instead of many passwords
against one account, the attacker tries one or two common passwords against many accounts.
This keeps the per-account failure count low enough to avoid lockout thresholds. The detection
key is grouping failures by source IP and counting distinct target accounts. If one IP hits
10+ accounts with only 1-3 attempts each, that is almost certainly a spray.

## SSH Brute Force

This is a well-understood pattern, but I wanted the Wazuh rules to go beyond simple
threshold alerts. The correlation chain is: individual failure, then a cluster of failures
from the same IP, then a successful login from a previously-bruteforcing IP. That last
rule (100103) is the high-value detection because it indicates the brute force worked.

## PowerShell Indicators

Encoded commands, download cradles, execution policy bypasses, and AMSI bypass attempts.
These are well-documented in the ATT&CK knowledge base under T1059.001. The Wazuh rules
match against Sysmon Event ID 1 (process creation) forwarded to the agent. The AMSI bypass
rule is the highest severity because it almost always indicates intentional defense evasion.

## Web Shell Detection

Web shells are tricky because the file drop itself is hard to catch without file integrity
monitoring. I focused on the behavioral side instead: web server processes spawning command
shells, script files appearing in web root directories, and network reconnaissance tools
running as children of httpd or w3wp. The file naming rule (looking for "shell", "cmd",
"backdoor" in filenames) catches lazy attackers but will miss anything with randomized names.

## Ransomware Behavior

Rather than writing signatures for specific ransomware families (which change constantly),
I focused on the behaviors that are common across almost all ransomware: mass file renaming
with new extensions, ransom note creation, shadow copy deletion, and rapid file modification
across directories. The shadow copy deletion rule is particularly important because it is
one of the last steps before encryption starts, which gives a narrow window for response.

## Linux Privilege Escalation

Focused on sudo abuse, SUID exploitation, critical file modification, and kernel module
loading. The sudo failure chain mirrors the SSH brute force logic: individual failures
escalate to a correlation rule when they cluster. SUID execution from writable directories
(/tmp, /dev/shm) is a strong indicator of privilege escalation tooling.
