<#
    Device operations against the cloud (Microsoft Graph): the INTUNE managed device and the ENTRA ID
    device object -- two SEPARATE objects for the same physical machine.

    Lookups return a normalized per-store result @{ Found; Id; Count; Detail; Reason; Error } and never
    throw, so the Devices page can build a clean status line per store. Deletes live in the UI layer
    (Invoke-DeviceCleanup) where the destructive confirmation + Multi-Admin-Approval handling belong.

    INTUNE + MULTI-ADMIN APPROVAL: when the tenant gates device delete behind Multi-Admin Approval, the
    Graph DELETE does NOT execute -- it returns HTTP 403 with an "ApprovalRequired" code and the op waits
    for a second admin. So the delete goes through Invoke-MgGraphRequest (to set the justification header
    and read the response), branching 204 (deleted) / 403-ApprovalRequired (pending) / other (error).
#>

function Find-IntuneDevice {
    <# Per-store lookup of the Intune managed device by hostname. Never throws. #>
    param([Parameter(Mandatory)][string]$Name)
    try {
        $q = $Name.Replace("'", "''")
        $r = Invoke-MgGraphRequest -Method GET -OutputType Hashtable -ErrorAction Stop `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=deviceName eq '$q'"
        $vals = @($r.value)
        if ($vals.Count -eq 0) { return @{ Found = $false; Reason = 'Not found in Intune.' } }
        $d = $vals[0]
        return @{
            Found  = $true; Id = [string]$d.id; Count = $vals.Count
            Detail = (@("$([string]$d.operatingSystem) $([string]$d.osVersion)".Trim(), "last sync $([string]$d.lastSyncDateTime)") -join '; ')
        }
    } catch {
        return @{ Found = $false; Reason = "Intune lookup failed: $($_.Exception.Message)"; Error = $true }
    }
}

function Find-EntraDevice {
    <# Per-store lookup of the Entra ID device object by display name (the directory object, distinct from
       the Intune managed device). Never throws. #>
    param([Parameter(Mandatory)][string]$Name)
    try {
        $q = $Name.Replace("'", "''")
        $r = Invoke-MgGraphRequest -Method GET -OutputType Hashtable -ErrorAction Stop `
            -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=displayName eq '$q'"
        $vals = @($r.value)
        if ($vals.Count -eq 0) { return @{ Found = $false; Reason = 'Not found in Entra ID.' } }
        $d = $vals[0]
        return @{
            Found  = $true; Id = [string]$d.id; Count = $vals.Count   # id = directory object id, used by the delete
            Detail = (@("join: $([string]$d.trustType)", "enabled: $([string]$d.accountEnabled)") -join '; ')
        }
    } catch {
        return @{ Found = $false; Reason = "Entra device lookup failed: $($_.Exception.Message)"; Error = $true }
    }
}

function Remove-EntraDeviceObject {
    <# Delete the Entra ID device object. Throws on failure (caller collects per-store results). #>
    param([Parameter(Mandatory)][string]$Id)
    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/devices/$Id" -ErrorAction Stop | Out-Null
}

# --- Multi-Admin-Approval requests (beta operationApprovalRequests, via RAW Invoke-MgGraphRequest --
#     deliberately NO Microsoft.Graph.Beta.* module, to avoid the assembly-version conflict) -----------

function Get-PendingApprovalRequests {
    <# Pending Multi-Admin-Approval requests (status = needsApproval) so a different admin can approve them.
       Reads the beta operationApprovalRequests collection. Throws on failure (caller surfaces it). #>
    $r = Invoke-MgGraphRequest -Method GET -OutputType Hashtable -ErrorAction Stop `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests?`$filter=status eq 'needsApproval'"
    return @($r.value)
}

function Submit-OperationApprovalDecision {
    <# Approve or reject a pending operationApprovalRequest. $Decision = 'approve' | 'reject'. Delegated /
       interactive ONLY (app auth can't), and you cannot approve your OWN request (the service enforces
       separation of duties). Raw beta POST. Throws on failure. #>
    param([Parameter(Mandatory)][string]$Id, [ValidateSet('approve', 'reject')][string]$Decision, [string]$Justification = '')
    $body = @{ justification = $Justification; approvalSource = 'adminConsole' }
    Invoke-MgGraphRequest -Method POST -Body $body -ErrorAction Stop `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests/$Id/$Decision" | Out-Null
}

function Test-IntuneApprovalRequiredResponse {
    <# PURE: given an error record from a managed-device DELETE, is this the EXPECTED Multi-Admin-Approval
       403 ("ApprovalRequired") rather than a real failure? Match on the documented code/text; default to
       NOT-approval so a genuine 403 (permissions) is still surfaced as an error. #>
    param($ErrorRecord)
    $msg = "$($ErrorRecord.Exception.Message)"
    if ($msg -notmatch '403|[Ff]orbidden|Approval') { return $false }
    return ($msg -match 'ApprovalRequired|Multi.?Admin|operationApproval|requires approval|pending approval')
}
