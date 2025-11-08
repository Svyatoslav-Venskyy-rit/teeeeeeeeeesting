<#
  CCDC Password Reset Script (LIVE)
  - Changes passwords for all enabled local users (and domain users if AD module is present)
  - Excludes any username containing whitelist substrings (case-insensitive)
  - Uses a single new password for all targets (edit $NewPassword below)
  - Exports a CSV report of actions taken
  - Includes safety confirmation prompt before changes
  - For domain users: Forces change at next logon and disables "PasswordNeverExpires"
#>

# ============================================
# === EDIT THIS LINE FOR THE NEW PASSWORD ===
# ============================================
$NewPassword = 'YourNewSecurePasswordHere123!'  # <- Change this to your chosen password

# Whitelist substrings (case-insensitive) - accounts containing these are skipped
# The regex match is case-insensitive by default in PowerShell's -match operator.
$whitelistPatterns = @(
    'datadog', 'dd-dog',
    'whiteteam', 'blackteam', 'grayteam',
    'fathertime',
    'chronos', 'aion', 'kairos', 'merlin', 'terminator', 'mrpeabody', 'jamescole', 'docbrown', 'professorparadox',
    'drwho', 'martymcfly', 'arthurdent', 'sambeckett', 'loki', 'riphunter', 'theflash', 'tonystark', 'drstrange', 'bartallen'
)

# Build regex to match any whitelist substring (escaped for safety)
# The use of [regex]::Escape() is a great safety measure.
$regex = ($whitelistPatterns | ForEach-Object { [regex]::Escape($_) }) -join '|'

# Output file with timestamp
$timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$outCsv = ".\ccdc_password_reset_$timestamp.csv"

# Initialize report array
$report = @()

# Safety confirmation (CRITICAL - do not remove)
Write-Host "WARNING: This script will change passwords on ALL enabled non-whitelisted accounts!" -ForegroundColor Red
Write-Host "New password: '$NewPassword'" -ForegroundColor Yellow
$confirm = Read-Host "Type 'CONFIRM' to proceed with changes (or anything else to abort)"
if ($confirm -ne 'CONFIRM') {
    Write-Host "Aborted by user. No changes made." -ForegroundColor Green
    exit
}

# Pre-calculate the secure string once for efficiency
$securePw = ConvertTo-SecureString $NewPassword -AsPlainText -Force

# --- Local Users ---
Write-Host "`n--- Processing Local Users ---" -ForegroundColor Cyan
try {
    # Only get enabled users to reduce loop size slightly
    $localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true } -ErrorAction Stop
} catch {
    Write-Warning "Get-LocalUser not available or failed. Skipping local users."
    $localUsers = @()
}

foreach ($u in $localUsers) {
    # Check whitelist first, since we pre-filtered for enabled users
    $isWhitelisted = $u.Name -match $regex
    
    # Create the report entry object
    $entry = [PSCustomObject]@{
        Environment = 'Local'
        AccountName = $u.Name
        Enabled = $true # Already filtered by Where-Object above
        Whitelisted = $isWhitelisted
        Action = ''
        Result = ''
        ErrorMessage = ''
    }

    if (-not $isWhitelisted) {
        try {
            # Use the pre-calculated secure string
            Set-LocalUser -Name $u.Name -Password $securePw -ErrorAction Stop
            $entry.Action = 'Password Changed'
            $entry.Result = 'Success'
            Write-Host "SUCCESS -> Local: $($u.Name)" -ForegroundColor Green
        } catch {
            $entry.Action = 'Attempted Change'
            $entry.Result = 'Failed'
            # Use $_.Exception.Message for cleaner error output
            $entry.ErrorMessage = $_.Exception.Message
            Write-Warning "FAILED -> Local: $($u.Name) - $($_.Exception.Message)"
        }
    } else {
        $entry.Action = 'Skipped'
        $entry.Result = 'No Action'
        Write-Host "SKIP (Whitelist match) -> Local: $($u.Name)" -ForegroundColor Gray
    }
    $report += $entry
}

# --- Domain Users (optional, only if ActiveDirectory module available) ---
Write-Host "`n--- Processing Domain Users (Active Directory) ---" -ForegroundColor Cyan
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # Get only enabled domain users
        $adUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties SamAccountName, PasswordNeverExpires, ChangePasswordAtLogon -ErrorAction Stop
        
        foreach ($u in $adUsers) {
            $sam = $u.SamAccountName
            $isWhitelisted = $sam -match $regex
            
            $entry = [PSCustomObject]@{
                Environment = 'Domain'
                AccountName = $sam
                Enabled = $true
                Whitelisted = $isWhitelisted
                Action = ''
                Result = ''
                ErrorMessage = ''
            }

            if (-not $isWhitelisted) {
                try {
                    # 1. Reset password
                    Set-ADAccountPassword -Identity $sam -NewPassword $securePw -Reset -ErrorAction Stop
                    
                    # 2. Set policy flags
                    # Ensure PasswordNeverExpires is false and force change at next logon
                    Set-ADUser -Identity $sam -ChangePasswordAtLogon $true -PasswordNeverExpires $false -ErrorAction Stop
                    
                    $entry.Action = 'Password Changed + Force Next Logon + No Expires'
                    $entry.Result = 'Success'
                    Write-Host "SUCCESS -> Domain: $sam" -ForegroundColor Green
                } catch {
                    $entry.Action = 'Attempted Change'
                    $entry.Result = 'Failed'
                    $entry.ErrorMessage = $_.Exception.Message
                    Write-Warning "FAILED -> Domain: $sam - $($_.Exception.Message)"
                }
            } else {
                $entry.Action = 'Skipped'
                $entry.Result = 'No Action'
                Write-Host "SKIP (Whitelist match) -> Domain: $sam" -ForegroundColor Gray
            }
            $report += $entry
        }
    } catch {
        Write-Warning "ActiveDirectory module error or AD query failed: $($_.Exception.Message)"
        $entry = [PSCustomObject]@{
            Environment = 'Domain'
            AccountName = 'N/A'
            Enabled = $false
            Whitelisted = $false
            Action = 'Skipped'
            Result = 'Error'
            ErrorMessage = "AD operation failed: $($_.Exception.Message)"
        }
        $report += $entry
    }
} else {
    Write-Host "ActiveDirectory module not available — skipping domain users." -ForegroundColor Yellow
    $entry = [PSCustomObject]@{
        Environment = 'Domain'
        AccountName = 'N/A'
        Enabled = $false
        Whitelisted = $false
        Action = 'Skipped'
        Result = 'Module Missing'
        ErrorMessage = 'ActiveDirectory module not available'
    }
    $report += $entry
}

# --- Report and Summary ---
# Export CSV report
$report | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

# Summary
$successCount = ($report | Where-Object { $_.Result -eq 'Success' }).Count
$failCount = ($report | Where-Object { $_.Result -eq 'Failed' }).Count
$skipCount = ($report | Where-Object { $_.Result -eq 'No Action' }).Count
Write-Host "`n--- Summary ---" -ForegroundColor Cyan
Write-Host "Success: $successCount | Failures: $failCount | Skipped: $skipCount" -ForegroundColor White
Write-Host "Full report: $outCsv" -ForegroundColor Green
Write-Host "Completed password reset actions." -ForegroundColor White
Write-Host "Remember: Domain users now have 'ChangePasswordAtLogon' set to true." -ForegroundColor Yellow
