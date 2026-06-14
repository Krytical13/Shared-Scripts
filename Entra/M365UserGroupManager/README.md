# M365 User / Group Manager

A polished WinForms GUI for **creating and modifying Microsoft Entra ID / Microsoft 365 users and groups** across multiple tenants. The form is **configurable**: a Settings dialog lets you choose exactly which attributes appear, and each attribute renders as the most sensible input control (text box, drop-down, checkbox, date picker, multi-value list, or person picker).

> Unlike the small drop-and-run scripts elsewhere in this repo, this is a **proper PowerShell module** organised for ongoing maintenance.

---

## What it does

- **Connect to Microsoft 365** with interactive (delegated) sign-in. Each sign-in is **remembered as an account** (no tenant-ID typing); a **Switch account** picker lets you hop between saved subsidiary tenants. Tokens persist (`-ContextScope CurrentUser`) and switching does **not** disconnect, so re-connecting a recently-used tenant is silent — built for a helpdesk tech bouncing between tenants all day.
- **Users tab** — create a new user or search/select an existing one to edit. Supports:
  - All common writable attributes (name, job/org, contact, address, account, usage location, …)
  - **Manager** assignment (search-and-pick)
  - **License** assign/remove (reads the tenant's SKUs)
  - **Enable / disable** the account and **reset password** (force-change options)
  - **Exchange extension attributes 1–15** (`onPremisesExtensionAttributes`) — editable for cloud-only users, shown read-only for directory-synced users
  - **Soft-delete** (recoverable for 30 days), gated behind a typed-name confirmation
- **Groups tab** — create or edit **Security** and **Microsoft 365** groups, with **members** and **owners** managed by search-and-pick. Type-defining fields are locked when editing (Graph can't change them after creation).
- **Exchange tab** — for objects only Exchange Online can manage. It's **gated**: until you click *Connect to Exchange Online* it shows a one-line explainer, not a surprise login. Once activated, a type selector covers **distribution lists**, **mail-enabled security groups**, and **shared / room / equipment mailboxes** — with members + owners (groups) or **Full Access / Send As / Send-on-Behalf** delegates (mailboxes). Exchange uses a separate sign-in from Graph and auto-disconnects when you switch/disconnect the Graph tenant.
- **Backup / restore** — on any selected object, **Backup…** writes a JSON snapshot of its *configuration* (attributes + members/owners/delegates/licenses; **not** mailbox contents, and passwords are never captured). **Restore…** loads a snapshot back into the form — recreating/cloning in New mode or reverting in Edit mode — and nothing is written until you click Create/Save.
- **Settings** — per-tab checkboxes over the full attribute catalog decide which fields show (Users/Groups). Your choices (and your saved accounts) persist to `%APPDATA%\M365UserGroupManager\config.json`.

---

## Requirements

- **Windows**, Windows PowerShell **5.1** or PowerShell **7+** (the launcher relaunches itself in STA if needed).
- Microsoft Graph SDK sub-modules (the launcher offers to install them for the current user if missing):
  - `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Users.Actions`, `Microsoft.Graph.Groups`, `Microsoft.Graph.Identity.DirectoryManagement`
- For the **Exchange tab** only: the `ExchangeOnlineManagement` module (offered for install when you first activate Exchange) and an **Exchange admin** role (Exchange Administrator, or Recipient Management). Exchange uses its own RBAC roles, not Graph scopes.
- An account with sufficient **Entra admin role** (e.g. User Administrator / Groups Administrator) — delegated scopes alone are not enough for directory writes.

### Delegated scopes requested on connect

| Scope | Used for |
|---|---|
| `User.ReadWrite.All` | create / modify / enable-disable / reset-password / soft-delete users |
| `Group.ReadWrite.All` | create / modify / soft-delete groups; manage owners |
| `GroupMember.ReadWrite.All` | add / remove group members |
| `Organization.Read.All` | read subscribed SKUs (license names) |
| `LicenseAssignment.ReadWrite.All` | assign / remove user licenses |

`Directory.ReadWrite.All` is intentionally **not** requested — the granular scopes above cover everything this tool does.

---

## Running it

```powershell
# From the module folder:
.\Start-M365UserGroupManager.ps1
```

Or import the module and call the entry point yourself:

```powershell
Import-Module .\M365UserGroupManager.psd1
Show-M365UserGroupManager
```

---

## Project layout

```
M365UserGroupManager/
├── M365UserGroupManager.psd1        # module manifest
├── M365UserGroupManager.psm1        # root: loads catalog, dot-sources Private/Public, exports
├── Start-M365UserGroupManager.ps1   # launcher: STA shim + module bootstrap + Show
├── README.md
├── Data/
│   └── AttributeCatalog.psd1        # declarative attribute schema (the single source of truth)
├── Private/
│   ├── Configuration.ps1            # load/save %APPDATA% config (saved accounts + enabled attributes)
│   ├── GraphValues.ps1              # Get-GraphVal / Format-Cell helpers
│   ├── GraphConnection.ps1          # connect / disconnect / switch tenant; scope + context
│   ├── GraphUsers.ps1               # user search / get / create / update / delete / pw / enable
│   ├── GraphGroups.ps1              # group search / get / create / update / members / owners
│   ├── GraphLicensing.ps1           # SKU map + license assignment
│   ├── ExchangeConnection.ps1       # Exchange Online connect / disconnect / status (lazy)
│   ├── ExchangeRecipients.ps1       # DL / mail-enabled security / mailbox + delegate ops
│   ├── BackupRestore.ps1            # config-snapshot export + load-into-form restore
│   ├── UiTheme.ps1                  # fonts, colours, button styling, Set-Progress
│   ├── UiFieldFactory.ps1           # schema -> control factory; read / set / dirty-diff
│   ├── UiPersonPicker.ps1           # search-and-pick dialog (Graph or Exchange source)
│   ├── UiSettingsDialog.ps1         # per-tab attribute checkboxes
│   ├── UiExchangeTab.ps1            # gated Exchange tab (activation + recipient forms)
│   └── UiMainForm.ps1               # main window (connect bar + Users/Groups/Exchange tabs)
├── Public/
│   └── Show-M365UserGroupManager.ps1  # public entry point
└── Tests/
    ├── Catalog.Tests.ps1            # catalog integrity (Pester 5)
    ├── Logic.Tests.ps1             # config round-trip + dirty-diff payload logic (Pester 5)
    └── Invoke-OfflineChecks.ps1     # dependency-free parse / import / form-build smoke test
```

---

## Design notes & Graph caveats (verified against Microsoft Learn)

- **Extension attributes** `extensionAttribute1–15` live under `onPremisesExtensionAttributes`. They are writable via Graph **only for cloud-only users**; for directory-synced users (and cloud-only users *previously* synced from on-prem AD) they are **read-only** in Graph and must be managed in Exchange. The form greys them out for synced users and surfaces write failures cleanly.
- **`proxyAddresses` is read-only via Graph** (recalculated from `mail`) even for cloud-only users — shown read-only.
- **`manager`** is a relationship, set via `Set-MgUserManagerByRef` (not a plain property).
- **Licenses** use `Set-MgUserLicense` (in `Microsoft.Graph.Users.Actions`); `usageLocation` must be set first.
- **Group type** (Security vs Microsoft 365) and `mailEnabled` are **immutable after creation** — locked in Edit mode. Mail-enabled security groups and distribution lists can't be created via Graph (Exchange only) and aren't offered.
- **Group membership** is incremental: edits are applied as add/remove `$ref` operations (no wholesale replace). Member removal uses `Remove-MgGroupMemberDirectoryObjectByRef`.
- **Account switching** does **not** disconnect — it calls `Connect-MgGraph -TenantId …` with `-ContextScope CurrentUser`, requesting the full scope set on every connect. Because tokens persist in the MSAL cache, re-selecting a recently-used account reconnects silently (no prompt). Each successful sign-in is auto-saved as an account so you never type a tenant ID. (`Disconnect-MgGraph` is only used by the explicit **Disconnect** button — it clears the cache, which would force a fresh prompt next time.)
- **Edit mode is dirty-aware**: only fields you actually change are sent in the PATCH.

---

## License

[MIT](../../LICENSE). Touches production identity systems — **test in a non-production tenant first.**
