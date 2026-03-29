# From Gap to Deployed Detection — Sigma Workflow

When you record a `GAP` or `BLIND_SPOT` verdict, PAS automatically generates
a Sigma rule scaffold. This guide walks you through taking that scaffold to a
deployed, validated detection in Sentinel.

## What PAS Generates

After a GAP/BLIND_SPOT verdict, PAS creates a file in `results\sigma\`:

```
results\
  sigma\
    T1053.005_scheduled_task_pas.yml
```

The scaffold is pre-populated with:
- A generated UUID
- The ATT&CK technique and tactic tags
- The correct logsource category (inferred from step types)
- A false positive hint based on the technique
- The gap type you recorded
- The run ID and date for traceability

## Step 1 — Edit the Scaffold

Open the generated file and fill in every `FILL IN` and `PLACEHOLDER` section.

The most important section is `detection.selection`. Use the events you
observed (or expected) in your SIEM to write the conditions.

**Example — scheduled task via schtasks.exe:**

```yaml
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  condition: selection
```

**Example — registry run key persistence:**

```yaml
detection:
  selection:
    TargetObject|contains:
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\'
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\'
  condition: selection
```

**Example — LSASS handle access:**

```yaml
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x143a'
  condition: selection
```

## Step 2 — Validate the Rule

Install sigma-cli if you haven't:

```bash
pip install sigma-cli
```

Check the rule:

```bash
sigma check results\sigma\T1053.005_scheduled_task_pas.yml
```

Fix any reported errors before converting.

## Step 3 — Convert to KQL

```bash
# Microsoft 365 Defender / MDE Advanced Hunting
sigma convert -t microsoft365defender -p windows \
    results\sigma\T1053.005_scheduled_task_pas.yml

# Microsoft Sentinel (via Uncoder or sigma-cli)
sigma convert -t sentinel -p windows \
    results\sigma\T1053.005_scheduled_task_pas.yml
```

Alternatively, paste the Sigma YAML into [Uncoder.io](https://uncoder.io) for
a web-based conversion with no tooling required.

## Step 4 — Deploy to Sentinel

1. In Sentinel, go to **Analytics → Create → Scheduled query rule**
2. Paste the converted KQL
3. Set the rule name, description, and ATT&CK mapping from the Sigma file
4. Configure severity, frequency, and lookback period
5. Save and enable

## Step 5 — Validate the Detection

Re-run the PAS scenario that generated the gap:

```powershell
.\pas_runner.ps1 -Scenario scenarios\persistence\T1053.005_scheduled_task.yml
```

Check whether the new Sentinel rule fired. Enter your verdict.
If the verdict is now `COVERED`, the loop is closed.

## Step 6 — Commit to SIEM-UseCases

Move the validated Sigma file (and the converted KQL) to your
[SIEM-UseCases](https://github.com/stanleytobias/SIEM-UseCases) repo.
Update the PAS result JSON `sigma_rule_path` to point to the committed location.

## Tips

- **False positives come first.** Before deploying in alert mode, run the
  rule in observation mode for a week to baseline false positive rate.

- **Tag everything.** Always set the ATT&CK technique tag in the Sentinel rule.
  It surfaces in the incidents view and feeds your MITRE coverage report.

- **One rule per technique is a floor, not a ceiling.** A single behavioral
  detection for T1053.005 is a start. Add sub-technique variants, different
  parent processes, and LOLBin chaining as you find them.

- **Link back to PAS.** Add a comment in the KQL referencing the PAS run ID
  and scenario. Future you will thank present you.
