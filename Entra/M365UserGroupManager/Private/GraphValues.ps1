<#
    Graph value helpers.

    Microsoft Graph PowerShell returns objects in more than one shape: typed SDK models expose
    PascalCase properties, while $select-ed extras and extension data land in an
    AdditionalProperties dictionary keyed by the camelCase Graph name. These helpers read a
    value regardless of shape, and flatten any value to a display string.
#>

function Get-GraphVal {
    <#
        Read a Graph property by its camelCase Name from a typed SDK object (PascalCase),
        a hashtable/dictionary, or an object's AdditionalProperties bag. Returns $null if absent.
    #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }

    # Hashtable / generic Dictionary[string,object] both expose ContainsKey() (the non-generic
    # IDictionary.Contains() can't be bound by PowerShell on the generic dictionary).
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.ContainsKey($Name)) { return $Object[$Name] }
        $pascalKey = $Name.Substring(0, 1).ToUpper() + $Name.Substring(1)
        if ($Object.ContainsKey($pascalKey)) { return $Object[$pascalKey] }
        return $null
    }

    $pascal = $Name.Substring(0, 1).ToUpper() + $Name.Substring(1)
    $p = $Object.PSObject.Properties[$pascal]
    if ($p) { return $p.Value }
    $p2 = $Object.PSObject.Properties[$Name]
    if ($p2) { return $p2.Value }

    $ap = $Object.PSObject.Properties['AdditionalProperties']
    if ($ap -and $ap.Value -and ($ap.Value -is [System.Collections.IDictionary])) {
        if ($ap.Value.ContainsKey($Name)) { return $ap.Value[$Name] }
    }
    return $null
}

function Format-Cell {
    <# Flatten any Graph value to a single display string. #>
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime])              { return $Value.ToString('yyyy-MM-dd') }
    if ($Value -is [System.DateTimeOffset]) { return $Value.ToString('yyyy-MM-dd') }
    if ($Value -is [bool])                  { return $Value.ToString() }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return ($Value | ForEach-Object { "$_" }) -join '; '
    }
    return "$Value"
}

function ConvertTo-StringList {
    <# Normalise any Graph multi-value into a clean string[] (drops null/blank entries). #>
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) {
        $t = $Value.Trim()
        if ($t) { return @($t) } else { return @() }
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return @($Value | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    }
    return @("$Value")
}
