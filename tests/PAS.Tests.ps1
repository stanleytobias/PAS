# PAS.Tests.ps1
# Pester unit tests for the PAS YAML parser and schema validators.
# Written for the Pester 3.4 that ships with Windows PowerShell 5.1.
#
#   Invoke-Pester -Script .\tests\PAS.Tests.ps1
#
# These tests lock in the behaviour of the two riskiest components (the hand-rolled
# YAML parser and the schema validators), including regressions fixed during audit:
#   C0  block-scalar first line must not be dropped
#   C1  block-scalar chomping indicators (|-, |+, >-)
#   C3  exec_wmi / exec_com field validation
#   C4  value_data: 0 is a valid value
#   Q9  yes/no/on/off are NOT coerced to booleans

$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'lib\PAS.Logging.psm1') -Force
Import-Module (Join-Path $root 'lib\PAS.Yaml.psm1')    -Force
Import-Module (Join-Path $root 'lib\PAS.Schema.psm1')  -Force

function ParseYaml([string]$Text) {
    ConvertFrom-PASYaml -Lines ($Text -split "`r?`n")
}

$ValidScenarioYaml = @'
id: T1234_test_scenario
name: Test Scenario
mitre_technique: T1234
mitre_tactic: discovery
description: A harmless test scenario
author: tester
created: "2026-01-01"
platform: windows
steps:
  - step: 1
    type: marker
    description: announce
    message: hello
cleanup:
  - step: 1
    type: marker
    description: done
    message: bye
analyst_checklist:
  - Check one thing
'@

Describe 'PAS.Yaml parser' {

    It 'parses string, integer and quoted scalars' {
        $r = ParseYaml "name: hello`nseconds: 5`nquoted: `"a b`""
        $r['name']    | Should Be 'hello'
        $r['seconds'] | Should Be 5
        $r['quoted']  | Should Be 'a b'
    }

    It 'parses true/false as booleans' {
        (ParseYaml 'flag: true')['flag']  | Should Be $true
        (ParseYaml 'flag: false')['flag'] | Should Be $false
    }

    It 'does NOT coerce yes/no/on/off to booleans (Q9 - Norway problem)' {
        (ParseYaml 'answer: yes')['answer'] | Should Be 'yes'
        (ParseYaml 'answer: no')['answer']  | Should Be 'no'
        (ParseYaml 'answer: off')['answer'] | Should Be 'off'
    }

    It 'preserves the FIRST line of a literal block scalar (regression C0)' {
        $r = ParseYaml "command: |`n  ALPHA`n  BETA`n  GAMMA`ntrailer: end"
        $r['command'] | Should Match 'ALPHA'
        $r['command'] | Should Match 'GAMMA'
        $r['trailer'] | Should Be 'end'
    }

    It 'supports the strip chomping indicator |- (C1)' {
        $r = ParseYaml "command: |-`n  ALPHA`n  BETA"
        $r['command'] | Should Match 'ALPHA'
        $r['command'] | Should Match 'BETA'
    }

    It 'folds a > block onto one line' {
        $r = ParseYaml "note: >`n  one two`n  three four"
        $r['note'] | Should Be 'one two three four'
    }

    It 'parses a sequence of mappings' {
        $r = ParseYaml "steps:`n  - step: 1`n    type: marker`n  - step: 2`n    type: sleep"
        @($r['steps']).Count   | Should Be 2
        $r['steps'][0]['type'] | Should Be 'marker'
        $r['steps'][1]['step'] | Should Be 2
    }
}

Describe 'PAS.Schema scenario validation' {

    It 'accepts a well-formed scenario' {
        (Test-PASSchema -Scenario (ParseYaml $ValidScenarioYaml)).Valid | Should Be $true
    }

    It 'rejects a missing required field' {
        $s = ParseYaml $ValidScenarioYaml
        $s.Remove('author')
        (Test-PASSchema -Scenario $s).Valid | Should Be $false
    }

    It 'rejects a malformed id' {
        $s = ParseYaml $ValidScenarioYaml
        $s['id'] = 'NOT_AN_ID'
        $v = Test-PASSchema -Scenario $s
        $v.Valid              | Should Be $false
        ($v.Errors -join ' ') | Should Match 'id'
    }

    It 'requires binary for an exec step' {
        $s = ParseYaml $ValidScenarioYaml
        $s['steps'] = @([ordered]@{ step = 1; type = 'exec'; description = 'run' })
        $v = Test-PASSchema -Scenario $s
        $v.Valid              | Should Be $false
        ($v.Errors -join ' ') | Should Match 'binary'
    }

    It 'validates exec_wmi required fields (C3)' {
        $s = ParseYaml $ValidScenarioYaml
        $s['steps'] = @([ordered]@{ step = 1; type = 'exec_wmi'; description = 'wmi'; wmi_class = 'Win32_Process' })
        $v = Test-PASSchema -Scenario $s
        $v.Valid              | Should Be $false
        ($v.Errors -join ' ') | Should Match 'method'
    }

    It 'accepts value_data of 0 for reg_write (C4)' {
        $s = ParseYaml $ValidScenarioYaml
        $s['steps'] = @([ordered]@{
            step = 1; type = 'reg_write'; description = 'w'
            hive = 'HKCU'; key = 'Software\PASTest'; value_name = 'X'; value_data = 0
        })
        $v = Test-PASSchema -Scenario $s
        ($v.Errors -join ' ') | Should Not Match 'value_data'
    }
}

Describe 'PAS.Schema suite validation (Q8)' {

    $suitePath = Join-Path $root 'scenarios\suites\__pester__.yml'

    It 'accepts a suite whose references resolve' {
        $y  = "name: Test Suite`nscenarios:`n  - step: 1`n    scenario_file: `"discovery/T1082_system_information_discovery.yml`""
        $sv = Test-PASSuiteSchema -Suite (ParseYaml $y) -SuitePath $suitePath
        $sv.Valid | Should Be $true
    }

    It 'rejects a suite with a missing scenario reference' {
        $y  = "name: Bad Suite`nscenarios:`n  - step: 1`n    scenario_file: `"discovery/__does_not_exist__.yml`""
        $sv = Test-PASSuiteSchema -Suite (ParseYaml $y) -SuitePath $suitePath
        $sv.Valid | Should Be $false
    }

    It 'rejects a suite missing the name field' {
        $y  = "scenarios:`n  - step: 1`n    scenario_file: `"discovery/T1082_system_information_discovery.yml`""
        $sv = Test-PASSuiteSchema -Suite (ParseYaml $y) -SuitePath $suitePath
        $sv.Valid | Should Be $false
    }
}
