@{
    RootModule           = 'M365UserGroupManager.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = '2112a256-8b65-4c83-8e00-a9af479016eb'
    Author               = 'Krytical13'
    CompanyName          = 'Krytical13'
    Copyright            = '(c) Krytical13. MIT License.'
    Description          = 'WinForms GUI for creating and modifying Microsoft Entra ID / Microsoft 365 users and groups across multiple tenants, driven by a configurable, settings-based attribute form.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    # The Microsoft Graph SDK sub-modules are required at RUNTIME (for the Connect and data
    # paths) but are deliberately NOT declared in RequiredModules. That lets this module
    # import -- and the window open -- even before the SDK is installed, so the tool can
    # offer to install it on first use. The launcher (Start-M365UserGroupManager.ps1) and
    # the Connect path bootstrap them on demand from PrivateData.RequiredGraphModules below.
    FunctionsToExport    = @('Show-M365UserGroupManager')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Microsoft365', 'EntraID', 'Graph', 'WinForms', 'GUI', 'UserManagement', 'GroupManagement', 'Identity')
            LicenseUri   = 'https://github.com/Krytical13/Shared-Scripts/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/Krytical13/Shared-Scripts'
            ReleaseNotes = 'Initial release: multi-tenant connect/switch; create & modify users and groups; enable/disable; reset password; license assign/remove; soft-delete; configurable attribute form including extensionAttribute1-15.'
        }

        # Graph SDK sub-modules the launcher / Connect path ensures are installed.
        RequiredGraphModules = @(
            'Microsoft.Graph.Authentication'
            'Microsoft.Graph.Users'
            'Microsoft.Graph.Users.Actions'
            'Microsoft.Graph.Groups'
            'Microsoft.Graph.Identity.DirectoryManagement'
        )
    }
}
