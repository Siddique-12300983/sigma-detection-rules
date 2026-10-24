# sigma-detection-rules

A small set of [Sigma](https://sigmahq.io/) rules for detections I worked
through in my Active Directory lab: Kerberoasting, LLMNR/NBT-NS poisoning,
suspicious scheduled task creation, and a Defender exclusion being added. Each
rule is written against Windows event logs and maps to a MITRE ATT&CK technique.

These came out of my
[purple-team-journey](https://github.com/Siddique-12300983/purple-team-journey)
lab. The Kerberoasting rule in particular is grounded in what I actually saw:
see the note below on RC4 versus AES.

## What Sigma is

Sigma is a vendor-neutral format for writing detection rules in YAML. You write
the logic once, then convert it to whatever your SIEM speaks (Splunk SPL, an
Elastic query, Microsoft Sentinel KQL, and so on). It means a detection can be
shared and reviewed without being locked to one product, the way a YARA rule is
shared for files.

## The rules

| Rule | Event | Detects | ATT&CK |
|---|---|---|---|
| [kerberoasting_4769_rc4.yml](rules/kerberoasting_4769_rc4.yml) | 4769 | A service ticket requested with RC4 (`0x17`), the classic Kerberoasting sign | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| [llmnr_nbtns_poisoning.yml](rules/llmnr_nbtns_poisoning.yml) | Sysmon 3 | LLMNR (UDP 5355) or NBT-NS (UDP 137) responder traffic | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| [scheduled_task_creation_4698.yml](rules/scheduled_task_creation_4698.yml) | 4698 | A new scheduled task that runs cmd, a script host or encoded PowerShell | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| [defender_exclusion_added_5007.yml](rules/defender_exclusion_added_5007.yml) | 5007 | A path, process or extension added to Defender exclusions | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |

### A note on the Kerberoasting rule (RC4 vs AES)

The RC4 check (`TicketEncryptionType: 0x17`) is the standard Kerberoasting
indicator and still useful. But in my own lab, Windows Server 2025 refuses to
issue RC4 tickets, so a real roast there showed up as AES (`0x12`) in the 4769
event, and an RC4-only rule would have missed it entirely. On a modern AES-only
domain you need a behavioural signal as well: one account requesting tickets for
many different SPNs in a short window. My
[log-analyzer](https://github.com/Siddique-12300983/log-analyzer) does that
second check, and the full write-up is in
[labs/ad-lab/kerberoasting.md](https://github.com/Siddique-12300983/purple-team-journey/blob/main/labs/ad-lab/kerberoasting.md).

## Converting for a SIEM

Install [sigma-cli](https://github.com/SigmaHQ/sigma-cli) and a backend:

```bash
pip install sigma-cli pysigma-backend-splunk
```

Convert a rule:

```bash
# Splunk
sigma convert -t splunk --without-pipeline rules/kerberoasting_4769_rc4.yml
```

That produces, for the Kerberoasting rule:

```
EventID=4769 TicketEncryptionType="0x17" Status="0x0" NOT ServiceName="*$" NOT ServiceName="krbtgt"
```

Other backends work the same way, for example `pysigma-backend-elasticsearch`
for Elastic or `pysigma-backend-microsoft365defender` for Sentinel/Defender KQL.
In production you would add a processing pipeline (`-p <pipeline>`) so field
names match your log source; `--without-pipeline` keeps the examples simple.

The event IDs these rules use need to be collected first. The Security events
(4769, 4698) need the matching audit policy enabled, and the network and
Defender events need Sysmon and Defender logging forwarded to your SIEM.

## Validating the rules

Two checks run in CI and can be run locally:

```bash
pip install yamllint pysigma
yamllint -c .yamllint rules/      # YAML style and syntax
python validate.py                # Sigma structure: title, UUID id, logsource, detection, condition
```

`validate.py` confirms each rule parses and has the fields a Sigma rule needs.
`sigma check rules/` from sigma-cli does a deeper check and reports 0 errors on
these rules.

## License

MIT. See [LICENSE](LICENSE).
