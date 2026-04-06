# PAS.Yaml.psm1
# Lightweight YAML parser sufficient for PAS scenario files.
# Handles: scalars, quoted strings, block scalars (|, >), sequences, mappings.
# No external dependencies -- pure PowerShell.

function Import-PASYaml {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "YAML file not found: $Path"
    }

    $lines = Get-Content $Path -Encoding UTF8
    # Strip comments and blank leading lines
    $lines = $lines | ForEach-Object {
        if ($_ -match '^\s*#') { '' } else { $_ }
    }

    try {
        return ConvertFrom-PASYaml -Lines $lines
    } catch {
        throw "Failed to parse YAML file '$Path': $_"
    }
}

function ConvertFrom-PASYaml {
    param([string[]]$Lines)

    $script:_yaml_lines = $Lines
    $script:_yaml_pos   = 0

    return Parse-YamlMapping -Indent 0
}

function Get-CurrentLine {
    if ($script:_yaml_pos -ge $script:_yaml_lines.Count) { return $null }
    return $script:_yaml_lines[$script:_yaml_pos]
}

function Get-Indent {
    param([string]$Line)
    if ($null -eq $Line -or $Line.Trim() -eq '') { return -1 }
    return ($Line -replace '^(\s*).*', '$1').Length
}

function Parse-YamlValue {
    param([string]$Raw, [int]$BaseIndent)

    $v = $Raw.Trim()

    # Block scalar -- literal (|) or folded (>)
    if ($v -eq '|' -or $v -eq '>') {
        $fold = ($v -eq '>')
        $script:_yaml_pos++
        $blockLines = @()
        while ($script:_yaml_pos -lt $script:_yaml_lines.Count) {
            $l = $script:_yaml_lines[$script:_yaml_pos]
            if ($l.Trim() -eq '' -or (Get-Indent $l) -gt $BaseIndent) {
                $blockLines += $l.TrimStart()  # strip base indent
                $script:_yaml_pos++
            } else { break }
        }
        if ($fold) { return ($blockLines -join ' ').Trim() }
        return ($blockLines -join "`n").TrimEnd()
    }

    # Sequence inline: [a, b, c]
    if ($v -match '^\[(.+)\]$') {
        return $Matches[1] -split '\s*,\s*' | ForEach-Object { $_.Trim().Trim('"').Trim("'") }
    }

    # Quoted strings
    if ($v -match '^"(.*)"$') { return $Matches[1] }
    if ($v -match "^'(.*)'$") { return $Matches[1] }

    # Booleans
    if ($v -in @('true','yes','on'))  { return $true  }
    if ($v -in @('false','no','off')) { return $false }

    # Null
    if ($v -in @('null','~','')) { return $null }

    # Integer
    if ($v -match '^-?\d+$') { return [int]$v }

    return $v
}

function Parse-YamlMapping {
    param([int]$Indent)
    $map = [ordered]@{}

    while ($script:_yaml_pos -lt $script:_yaml_lines.Count) {
        $line = Get-CurrentLine
        if ($null -eq $line -or $line.Trim() -eq '') { $script:_yaml_pos++; continue }

        $lineIndent = Get-Indent $line
        if ($lineIndent -lt $Indent) { break }
        if ($lineIndent -gt $Indent) { $script:_yaml_pos++; continue }

        # Sequence item at this level
        if ($line.TrimStart() -match '^-\s*(.*)$') {
            break  # Caller handles sequences
        }

        # Key: value
        if ($line -match '^\s{' + $Indent + '}([^:]+):\s*(.*)$') {
            $key   = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            $script:_yaml_pos++

            if ($value -eq '' -or $value -in @('|','>')) {
                # Peek next line
                $nextLine = Get-CurrentLine
                $nextIndent = Get-Indent $nextLine

                if ($value -in @('|','>')) {
                    $map[$key] = Parse-YamlValue -Raw $value -BaseIndent $Indent
                } elseif ($null -ne $nextLine -and $nextLine.TrimStart() -match '^-\s') {
                    $map[$key] = Parse-YamlSequence -Indent $nextIndent
                } elseif ($null -ne $nextLine -and $nextIndent -gt $Indent) {
                    $map[$key] = Parse-YamlMapping -Indent $nextIndent
                } else {
                    $map[$key] = $null
                }
            } else {
                $map[$key] = Parse-YamlValue -Raw $value -BaseIndent $Indent
            }
        } else {
            $script:_yaml_pos++
        }
    }

    return $map
}

function Parse-YamlSequence {
    param([int]$Indent)
    $seq = @()

    while ($script:_yaml_pos -lt $script:_yaml_lines.Count) {
        $line = Get-CurrentLine
        if ($null -eq $line -or $line.Trim() -eq '') { $script:_yaml_pos++; continue }

        $lineIndent = Get-Indent $line
        if ($lineIndent -lt $Indent) { break }

        if ($line.TrimStart() -match '^-\s*(.*)$') {
            $itemValue = $Matches[1].Trim()
            $script:_yaml_pos++

            if ($itemValue -eq '') {
                # Block item -- next lines form a mapping
                $nextLine   = Get-CurrentLine
                $nextIndent = Get-Indent $nextLine
                if ($null -ne $nextLine -and $nextIndent -gt $Indent) {
                    $seq += , (Parse-YamlMapping -Indent $nextIndent)
                }
            } elseif ($itemValue -match '^([^:#]+):\s*(.*)$') {
                # Inline mapping: "- key: value" with possible continuation keys
                $inlineKey   = $Matches[1].Trim()
                $inlineValue = $Matches[2].Trim()
                $itemMap     = [ordered]@{}
                $itemMap[$inlineKey] = Parse-YamlValue -Raw $inlineValue -BaseIndent ($Indent + 2)

                $nextLine   = Get-CurrentLine
                $nextIndent = Get-Indent $nextLine
                if ($null -ne $nextLine -and $nextIndent -gt $Indent) {
                    $rest = Parse-YamlMapping -Indent $nextIndent
                    foreach ($k in $rest.Keys) { $itemMap[$k] = $rest[$k] }
                }
                $seq += , $itemMap
            } else {
                # Plain scalar value
                $seq += , (Parse-YamlValue -Raw $itemValue -BaseIndent $Indent)
            }
        } else {
            break
        }
    }
    return $seq
}

Export-ModuleMember -Function Import-PASYaml, ConvertFrom-PASYaml
