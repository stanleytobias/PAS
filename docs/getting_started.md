# Getting Started with PAS

## Prerequisites

- A Windows lab VM (isolated from production)
- PowerShell 5.1+ or PowerShell 7+
- Administrator privileges for most scenarios
- A SIEM and EDR you want to validate (Sentinel + MDE, Splunk + CrowdStrike, etc.)

## Setup

```powershell
git clone https://github.com/stanleytobias/PAS
cd PAS
```

No installation, no dependencies. PAS is pure PowerShell — just clone and run.

## First Run

Start with a dry run to see exactly what a scenario will do without executing anything:

```powershell
.\pas_runner.ps1 -DryRun -Scenario scenarios\persistence\T1053.005_scheduled_task.yml
```

Every step will be printed with its type and description. Nothing touches the system.

## Your First Validation Run

```powershell
.\pas_runner.ps1 -Scenario scenarios\persistence\T1053.005_scheduled_task.yml
```

PAS will:
1. Print a banner with technique and tactic
2. Execute each step in order
3. Run cleanup
4. Print the analyst checklist
5. Prompt you for a verdict

While the checklist is on screen, go to your SIEM and EDR and check for the listed events.
Then come back and enter your verdict.

## Validating All Scenario YAMLs

Before running anything, check all scenario files parse and conform to the schema:

```powershell
.\pas_runner.ps1 -Validate
```

## Next Steps

- See [workflow.md](workflow.md) for the full detection engineering loop
- See [hunt_mode.md](hunt_mode.md) for generating hunt artifacts
- See [writing_scenarios.md](writing_scenarios.md) to add your own scenarios
- See [sigma_workflow.md](sigma_workflow.md) to go from gap to deployed detection
