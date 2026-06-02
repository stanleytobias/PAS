# PAS.Logging.psm1
# Centralised logging with colour, verbosity control, and log file support.

$script:PAS_QUIET   = $false
$script:PAS_VERBOSE = $false
$script:PAS_LOGFILE = $null

function Set-PASLogging {
    param(
        [bool]$Quiet   = $false,
        [bool]$Verbose = $false,
        [string]$LogFile = $null
    )
    $script:PAS_QUIET   = $Quiet
    $script:PAS_VERBOSE = $Verbose
    $script:PAS_LOGFILE = $LogFile
}

function Write-PASLog {
    param(
        [string]$Message,
        [string]$Level = 'INFO',
        [ConsoleColor]$Color = [ConsoleColor]::White
    )
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $line      = "[$timestamp][$Level] $Message"

    if ($script:PAS_LOGFILE) {
        Add-Content -Path $script:PAS_LOGFILE -Value $line -Encoding UTF8
    }

    if ($script:PAS_QUIET -and $Level -notin @('ERROR', 'WARN')) { return }
    Write-Host $line -ForegroundColor $Color
}

function Write-PASInfo  { param([string]$m) Write-PASLog -Message $m -Level 'INFO'    -Color Cyan    }
function Write-PASWarn  { param([string]$m) Write-PASLog -Message $m -Level 'WARN'    -Color Yellow  }
function Write-PASError { param([string]$m) Write-PASLog -Message $m -Level 'ERROR'   -Color Red     }
function Write-PASStep  { param([string]$m) Write-PASLog -Message $m -Level 'STEP'    -Color White   }
function Write-PASOk    { param([string]$m) Write-PASLog -Message $m -Level 'OK'      -Color Green   }
function Write-PASDebug {
    param([string]$m)
    if ($script:PAS_VERBOSE) {
        Write-PASLog -Message $m -Level 'DEBUG' -Color DarkGray
    }
}

function Write-PASBanner {
    param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Cyan)
    if ($script:PAS_QUIET) { return }
    $line = '=' * 60
    Write-Host $line             -ForegroundColor $Color
    Write-Host "  $Text"         -ForegroundColor $Color
    Write-Host $line             -ForegroundColor $Color
}

Export-ModuleMember -Function *
