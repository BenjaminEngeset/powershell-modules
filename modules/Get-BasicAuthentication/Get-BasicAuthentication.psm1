
function Get-BasicAuthentication {
    <#
    .SYNOPSIS
        Finds usage of Basic authentication in Azure AD.
    .DESCRIPTION
        Traverses thru Azure AD Sign-in logs, finding usage of Basic authentication in the tenant in the last 30 days.
        If there is usage of Basic authentication, the result will be displayed for output and stored in a CSV (optionally).
        Prior to deprecation of Basic authentication in all tenants, it should be checked if it's used.
    .PARAMETER Path
        A optional parameter that specifies the location to save the CSV output file.
    .EXAMPLE
        Get-BasicAuthentication -Path 'C:\Temp\TenantBasicAuthentication.csv' -Verbose
    .NOTES
        Author: bengeset96
        Version: 1.0.1
    #>
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = 'A optional parameter that specifies the location to save the CSV output file.')]
        [string]$Path
    )

    Select-MgProfile -Name 'beta'

    $basicAuth = 'Exchange Online PowerShell', 'Exchange ActiveSync', 'POP', 'IMAP', 'MAPI Over HTTP', 'Exchange Web Services', 'Offline Address Book', 'Universal Outlook'
    | Join-String -Separator ' or ' -Property { "ClientAppUsed eq '{0}'" -f $_ }

    $logs = Get-MgAuditLogSignIn -Filter $basicAuth
    if ($Path -and $logs) {
        Write-Verbose 'Exporting the result'
        $logs | Export-Csv $Path
    }
    else {
        if ($logs) {
            $logs
        }
        else {
            Write-Host 'No signs of basic authentication found in the last 30 days.' -ForegroundColor Green
        }
    }
    Write-Verbose 'Signing out'
    Disconnect-MgGraph
}