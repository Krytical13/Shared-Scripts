<#
    Exchange Online recipient operations.

    Every EXO cmdlet runs INSIDE the dedicated runspace via Invoke-ExoCommand (see
    ExchangeConnection.ps1) -- the session lives there and the UI never blocks. Same-process
    runspace means objects come back live (no serialization), so callers read properties normally.

    Functions that need per-item recipient resolution (members / owners / delegates) do that
    resolution inside the runspace scriptblock and return plain person-info hashtables
    @{ Id; DisplayName; Detail; Type } (Id = primary SMTP, the stable identity used for add/remove).
#>

# ----------------------------------------------------------------- search / resolve

function Search-ExoRecipient {
    <# ANR (or browse-first-N when blank) across recipients, optionally filtered by type. #>
    param([string]$Query, [string[]]$RecipientTypeDetails, [int]$Top = 100)
    Invoke-ExoCommand -Parameters @{ Query = $Query; Types = $RecipientTypeDetails; Top = $Top } -Script {
        param($Query, $Types, $Top)
        $r = if ([string]::IsNullOrWhiteSpace($Query)) { Get-Recipient -ResultSize $Top -ErrorAction Stop }
        else { Get-Recipient -Anr $Query -ResultSize $Top -ErrorAction Stop }
        if ($Types) { $r = $r | Where-Object { $Types -contains [string]$_.RecipientTypeDetails } }
        $r | Sort-Object DisplayName | Select-Object DisplayName, PrimarySmtpAddress, RecipientTypeDetails, ExternalDirectoryObjectId
    }
}

function ConvertTo-ExoPersonInfo {
    <# Normalise a recipient-shaped object to @{ Id; DisplayName; Detail; Type }. Used in the UI
       runspace on objects returned by Search-ExoRecipient. #>
    param($Object, [string]$IdentityOverride)
    $smtp = [string]$Object.PrimarySmtpAddress
    $id = if ($IdentityOverride) { $IdentityOverride } elseif ($smtp) { $smtp } else { [string]$Object.Name }
    @{
        Id          = $id
        DisplayName = [string]$Object.DisplayName
        Detail      = if ($smtp) { $smtp } else { $id }
        Type        = [string]$Object.RecipientTypeDetails
    }
}

function Resolve-ExoRecipientInfo {
    <# Resolve a set of identities (e.g. GrantSendOnBehalfTo) to person-info hashtables. #>
    param($Identities)
    if (-not $Identities) { return @() }
    Invoke-ExoCommand -Parameters @{ Ids = @($Identities | ForEach-Object { [string]$_ }) } -Script {
        param($Ids)
        foreach ($x in $Ids) {
            $rec = try { Get-Recipient -Identity $x -ErrorAction Stop } catch { $null }
            if ($rec) {
                $smtp = [string]$rec.PrimarySmtpAddress
                @{ Id = $(if ($smtp) { $smtp } else { [string]$x }); DisplayName = [string]$rec.DisplayName; Detail = $(if ($smtp) { $smtp } else { [string]$x }) }
            } else {
                @{ Id = [string]$x; DisplayName = [string]$x; Detail = [string]$x }
            }
        }
    }
}

# ----------------------------------------------------------------- distribution / mail-enabled security

function Get-ExoDistributionGroup {
    param([Parameter(Mandatory)][string]$Id)
    Invoke-ExoCommand -Parameters @{ Id = $Id } -Script { param($Id) Get-DistributionGroup -Identity $Id -ErrorAction Stop } | Select-Object -First 1
}

function New-ExoDistributionGroup {
    param([Parameter(Mandatory)][hashtable]$Params)
    Invoke-ExoCommand -Parameters @{ P = $Params } -Script { param($P) New-DistributionGroup @P -ErrorAction Stop } | Select-Object -First 1
}

function Set-ExoDistributionGroup {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][hashtable]$Params)
    Invoke-ExoCommand -Parameters @{ Id = $Id; P = $Params } -Script { param($Id, $P) Set-DistributionGroup -Identity $Id @P -ErrorAction Stop } | Out-Null
}

function Remove-ExoDistributionGroup {
    param([Parameter(Mandatory)][string]$Id)
    Invoke-ExoCommand -Parameters @{ Id = $Id } -Script { param($Id) Remove-DistributionGroup -Identity $Id -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop } | Out-Null
}

function Get-ExoDistributionGroupMemberInfo {
    param([Parameter(Mandatory)][string]$Id)
    Invoke-ExoCommand -Parameters @{ Id = $Id } -Script {
        param($Id)
        Get-DistributionGroupMember -Identity $Id -ResultSize Unlimited -ErrorAction Stop | ForEach-Object {
            $smtp = [string]$_.PrimarySmtpAddress
            @{ Id = $(if ($smtp) { $smtp } else { [string]$_.Name }); DisplayName = [string]$_.DisplayName; Detail = $(if ($smtp) { $smtp } else { [string]$_.Name }); Type = [string]$_.RecipientTypeDetails }
        }
    }
}

function Add-ExoDistributionGroupMember {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Member)
    Invoke-ExoCommand -Parameters @{ Id = $Id; M = $Member } -Script { param($Id, $M) Add-DistributionGroupMember -Identity $Id -Member $M -BypassSecurityGroupManagerCheck -ErrorAction Stop } | Out-Null
}

function Remove-ExoDistributionGroupMember {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Member)
    Invoke-ExoCommand -Parameters @{ Id = $Id; M = $Member } -Script { param($Id, $M) Remove-DistributionGroupMember -Identity $Id -Member $M -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop } | Out-Null
}

function Get-ExoDistributionGroupOwnerInfo {
    param([Parameter(Mandatory)][string]$Id)
    Invoke-ExoCommand -Parameters @{ Id = $Id } -Script {
        param($Id)
        $g = Get-DistributionGroup -Identity $Id -ErrorAction Stop
        foreach ($o in $g.ManagedBy) {
            $rec = try { Get-Recipient -Identity $o -ErrorAction Stop } catch { $null }
            if ($rec) {
                $smtp = [string]$rec.PrimarySmtpAddress
                @{ Id = $(if ($smtp) { $smtp } else { [string]$o }); DisplayName = [string]$rec.DisplayName; Detail = $(if ($smtp) { $smtp } else { [string]$o }); Type = [string]$rec.RecipientTypeDetails }
            } else {
                @{ Id = [string]$o; DisplayName = [string]$o; Detail = [string]$o; Type = '' }
            }
        }
    }
}

function Set-ExoDistributionGroupOwners {
    param([Parameter(Mandatory)][string]$Id, [string[]]$Owners)
    Invoke-ExoCommand -Parameters @{ Id = $Id; O = $Owners } -Script { param($Id, $O) Set-DistributionGroup -Identity $Id -ManagedBy $O -BypassSecurityGroupManagerCheck -ErrorAction Stop } | Out-Null
}

# ----------------------------------------------------------------- mailboxes (shared / room / equipment)

function Get-ExoMailbox {
    param([Parameter(Mandatory)][string]$Id)
    Invoke-ExoCommand -Parameters @{ Id = $Id } -Script { param($Id) Get-Mailbox -Identity $Id -ErrorAction Stop } | Select-Object -First 1
}

function New-ExoMailbox {
    param([Parameter(Mandatory)][hashtable]$Params)
    Invoke-ExoCommand -Parameters @{ P = $Params } -Script { param($P) New-Mailbox @P -ErrorAction Stop } | Select-Object -First 1
}

function Set-ExoMailbox {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][hashtable]$Params)
    Invoke-ExoCommand -Parameters @{ Id = $Id; P = $Params } -Script { param($Id, $P) Set-Mailbox -Identity $Id @P -ErrorAction Stop } | Out-Null
}

function Remove-ExoMailbox {
    param([Parameter(Mandatory)][string]$Id)
    Invoke-ExoCommand -Parameters @{ Id = $Id } -Script { param($Id) Remove-Mailbox -Identity $Id -Confirm:$false -ErrorAction Stop } | Out-Null
}

# Full Access delegates --------------------------------------------------------------------

function Get-ExoFullAccessInfo {
    param([Parameter(Mandatory)][string]$Id)
    Invoke-ExoCommand -Parameters @{ Id = $Id } -Script {
        param($Id)
        Get-MailboxPermission -Identity $Id -ErrorAction Stop |
            Where-Object { ($_.AccessRights -join ',') -match 'FullAccess' -and -not $_.IsInherited -and [string]$_.User -notlike 'NT AUTHORITY\*' } |
            ForEach-Object {
                $u = [string]$_.User
                $rec = try { Get-Recipient -Identity $u -ErrorAction Stop } catch { $null }
                if ($rec) { $smtp = [string]$rec.PrimarySmtpAddress; @{ Id = $(if ($smtp) { $smtp } else { $u }); DisplayName = [string]$rec.DisplayName; Detail = $(if ($smtp) { $smtp } else { $u }); Type = [string]$rec.RecipientTypeDetails } }
                else { @{ Id = $u; DisplayName = $u; Detail = $u; Type = '' } }
            }
    }
}

function Add-ExoFullAccess {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$User, [bool]$AutoMapping = $true)
    Invoke-ExoCommand -Parameters @{ Id = $Id; U = $User; A = $AutoMapping } -Script { param($Id, $U, $A) Add-MailboxPermission -Identity $Id -User $U -AccessRights FullAccess -InheritanceType All -AutoMapping $A -Confirm:$false -ErrorAction Stop } | Out-Null
}

function Remove-ExoFullAccess {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$User)
    Invoke-ExoCommand -Parameters @{ Id = $Id; U = $User } -Script { param($Id, $U) Remove-MailboxPermission -Identity $Id -User $U -AccessRights FullAccess -InheritanceType All -Confirm:$false -ErrorAction Stop } | Out-Null
}

# Send As delegates ------------------------------------------------------------------------

function Get-ExoSendAsInfo {
    param([Parameter(Mandatory)][string]$Id)
    Invoke-ExoCommand -Parameters @{ Id = $Id } -Script {
        param($Id)
        Get-RecipientPermission -Identity $Id -ErrorAction Stop |
            Where-Object { ($_.AccessRights -join ',') -match 'SendAs' -and [string]$_.Trustee -notlike 'NT AUTHORITY\*' } |
            ForEach-Object {
                $tr = [string]$_.Trustee
                $rec = try { Get-Recipient -Identity $tr -ErrorAction Stop } catch { $null }
                if ($rec) { $smtp = [string]$rec.PrimarySmtpAddress; @{ Id = $(if ($smtp) { $smtp } else { $tr }); DisplayName = [string]$rec.DisplayName; Detail = $(if ($smtp) { $smtp } else { $tr }); Type = [string]$rec.RecipientTypeDetails } }
                else { @{ Id = $tr; DisplayName = $tr; Detail = $tr; Type = '' } }
            }
    }
}

function Add-ExoSendAs {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Trustee)
    Invoke-ExoCommand -Parameters @{ Id = $Id; T = $Trustee } -Script { param($Id, $T) Add-RecipientPermission -Identity $Id -Trustee $T -AccessRights SendAs -Confirm:$false -ErrorAction Stop } | Out-Null
}

function Remove-ExoSendAs {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Trustee)
    Invoke-ExoCommand -Parameters @{ Id = $Id; T = $Trustee } -Script { param($Id, $T) Remove-RecipientPermission -Identity $Id -Trustee $T -AccessRights SendAs -Confirm:$false -ErrorAction Stop } | Out-Null
}
