# Hybrid (on-prem AD + Entra cloud) support — implementation plan

> Status: **planning / proposal**. Researched against Microsoft Learn (June 2026) with an adversarial
> verification pass; the corrected facts below supersede first-pass research where they disagree.
> Nothing here is built yet. Authored for the `M365UserGroupManager` module.

## 0. Guiding principle

The tool stays **cloud-first**. Hybrid is an **additive, gated capability**, exactly like the existing
Exchange tab: when the tenant isn't hybrid (or the workstation can't reach a DC), the experience is
unchanged. When it *is* hybrid, the tool detects each object's **Source of Authority (SOA)** and routes
each edit to the right place — with a clear badge so the operator always knows where a change will land.

The single worst outcome to avoid: silently sending an edit to the cloud that the cloud rejects (synced
objects are read-only in Graph) and leaving the operator confused. We **pre-gate** on SOA rather than
trial-and-error PATCH.

---

## 1. Feasibility summary

Adding hybrid support is **feasible and mostly built on GA APIs.** The hard part isn't any single call —
it's the *routing logic* and the *UX* for showing the operator where an edit goes. Overall: **medium**
effort, **high** value for an MSP/helpdesk that administers synced tenants.

| Capability | Status | How |
|---|---|---|
| Detect tenant is hybrid | **GA** | `Get-MgOrganization → OnPremisesSyncEnabled` |
| Detect per-object SOA | **GA** | `onPremisesSyncEnabled` on user/group/contact (true=synced, false=was-synced/orphaned, null=cloud-only) |
| Edit synced objects in on-prem AD | **GA** | RSAT `ActiveDirectory` module, or `System.DirectoryServices` (LDAP) fallback |
| DC auto-discovery | **GA** | `Get-ADDomainController -Discover -Writable`; fallback `System.DirectoryServices.ActiveDirectory.Domain` / `$env:LOGONSERVER` / `nltest /dsgetdc:` |
| Force **Connect Sync** | **GA** | `Start-ADSyncSyncCycle -PolicyType Delta` (server-local; remote via WinRM is community practice, not first-party-documented) |
| Force **Cloud Sync** | **GA** | Graph `synchronizationJob` *restart*, or per-user **on-demand provisioning** (restart ≠ delta — see §5) |
| Poll for a change landing in cloud | **GA** | `Get-MgUser -Property onPremisesLastSyncDateTime` |
| **Group** SOA conversion | **GA** (Oct 2025) | `PATCH /v1.0/groups/{id}/onPremisesSyncBehavior {isCloudManaged:true}` |
| **User / Contact** SOA conversion | **Public Preview** | same shape on `/v1.0/users|contacts/{id}/...` — gate behind a "Preview" toggle |
| Typed SOA SDK cmdlets | **beta-only** | `Update-MgBetaGroupOnPremiseSyncBehavior` — **avoid**; call `/v1.0` via `Invoke-MgGraphRequest` |

**Key correction from verification:** despite the Microsoft Graph *reference* pages for `onPremisesSyncBehavior`
rendering only under `/beta` (a documentation lag), the **GA production path for groups is the `/v1.0`
endpoint**. Hard-code `/v1.0` + `Invoke-MgGraphRequest`; do **not** take a dependency on the beta SDK module.

---

## 2. Environment & capability detection

Three independent signals, each gating a different feature set (mirror the Exchange-tab "calm empty-state"
pattern — never a surprise prompt):

1. **Is the tenant hybrid?** `Get-MgOrganization | Select OnPremisesSyncEnabled`. If false → hybrid UI stays
   dormant; tool behaves exactly as today.
2. **Can this workstation write to AD?** (a) is the machine domain-joined and can it locate a *writable* DC?
   (b) is the `ActiveDirectory` RSAT module present? Detect with
   `Get-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools*` (client) /
   `Get-WindowsFeature RSAT-AD-PowerShell` (server). If RSAT absent → offer install (admin) **or** fall back
   to the in-box `System.DirectoryServices` LDAP path.
3. **Is a sync server reachable for a *forced* sync?** Optional; if not, degrade to "edit saved — changes
   appear at the next sync (~30 min Connect / ~10–20 min Cloud)" with a manual refresh.

Each missing capability disables only its feature and explains why — it never blocks the cloud experience.

---

## 3. Source-of-authority routing (the core logic)

Per selected object, read `onPremisesSyncEnabled` (and, to catch mid-SOA-transfer objects,
`isCloudManaged`). Then route **per attribute**:

- **`null` / `false`** (cloud-only or already SOA-transferred) → edit in **cloud** (today's behavior).
- **`true`** (synced) → split by attribute authority:

| Authority class | Examples | Route to |
|---|---|---|
| **On-prem-mastered** (read-only in Graph) | displayName, given/surname, UPN, jobTitle, department, office, address, phones, **manager**, **extensionAttribute1–15**, proxyAddresses, **synced-group membership** | **On-prem AD** |
| **Cloud-authoritative even when synced** | **license assignment**, **usageLocation*** , membership of **cloud-only** groups, directory/app-role assignments, MFA/auth methods | **Cloud (Graph)** — keep editable |
| **Password** | reset/change | **AD directly**, *or* cloud reset only if **SSPR writeback** is configured |
| **Exchange-controlled** (hybrid) | proxyAddresses, custom attrs on remote mailboxes | **On-prem Exchange / EXO** per §9 |

`*` **usageLocation correction:** it is a *default-synced* attribute, so on a standard Connect tenant treat it
as **on-prem-mastered** unless proven otherwise — do not assume it's cloud-writable.

**Catalog encoding:** add an `Authority` key to each attribute hashtable in `AttributeCatalog.psd1`
(`Cloud` | `OnPrem` | `CloudWhenSynced` | `Exchange`) plus an `AdLdapName` for the on-prem attribute
(e.g. `jobTitle → title`, `department → department`, `mobilePhone → mobile`). The form already renders per
attribute; the factory just consults `Authority` + the object's SOA to decide editable/read-only and which
backend `Save` calls. This keeps the catalog the single source of truth.

**Gotchas baked into routing:**
- `onPremisesSyncEnabled` is a **three-state** flag — `false` ≠ cloud-only; it means "was synced, now
  orphaned" (editable in cloud but may carry stale on-prem* attributes).
- Dynamic groups (`groupTypes` contains `DynamicMembership`) are never member-editable, sync-independent.
- A blocked write surfaces as a 403/400, not a clean signal → **pre-gate**, don't catch-and-guess.

---

## 4. Editing on-prem AD

- **DC discovery:** `Get-ADDomainController -Discover -Writable` (DCLocator/DsGetDcName). RSAT-free fallback:
  `[DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()` (domain of the *machine*, credential-
  independent), `$env:LOGONSERVER`, or `nltest /dsgetdc:`. DsGetDcName does **not** verify reachability —
  try, then re-discover with force on failure.
- **Two write backends behind one abstraction:**
  - **RSAT path (preferred):** `Set-ADUser` (incl. `-Replace @{title=…; mobile=…}` for arbitrary attrs),
    `Set-ADGroup`, `Add-/Remove-ADGroupMember`, `Set-ADAccountPassword -Reset`, `Enable-/Disable-ADAccount`,
    `New-ADUser`. None work against an RODC → discovery must request `-Writable`.
  - **LDAP fallback (in-box, GA):** `System.DirectoryServices.DirectoryEntry` + `CommitChanges()` /
    `DirectorySearcher`. Windows-only; fine for both 5.1 (.NET FW) and 7 (.NET).
- **Cloud → on-prem object mapping (verified):** **match on `onPremisesSamAccountName` + `onPremisesDomainName`**
  (or bind directly via `onPremisesDistinguishedName`). Do **NOT** blindly decode `onPremisesImmutableId` — it's
  Base64 of the source anchor, which is `objectGUID` *or* `ms-DS-ConsistencyGuid` *or* even a string attribute
  depending on the Connect config, so a GUID decode is not version-safe.
- **Rights:** on-prem edits need delegated AD permissions on the target OU — **separate** from Graph scopes.
  Decide whether to use the tech's logged-in Windows identity or a prompted AD credential (see open questions).

---

## 5. Sync control (force + wait)

- **Which engine?** Connect Sync vs Cloud Sync changes everything. Detect, don't assume.
- **Connect Sync:** `Start-ADSyncSyncCycle -PolicyType Delta` — a real delta, but **server-local** (ADSync
  module, local admin rights). Remoting via `Invoke-Command`/WinRM works and is common, but Microsoft
  publishes no first-party "run it remotely" how-to, so treat it as best-effort and make the target server +
  creds configurable.
- **Cloud Sync:** the trigger is a **job *restart*, not a "delta now."** A restart (Graph
  `synchronizationJob` restart, or `Restart-AADCloudSyncToolsJob`) with `resetScope` clearing watermarks
  re-evaluates **all** objects — heavier than intended for a single edit. For one object prefer **on-demand
  provisioning** (a Cloud-Sync-only feature). Graph restart scope needs `Synchronization.ReadWrite.All` **and**
  a directory role (Hybrid Identity / Application / Cloud Application Administrator) — a plain helpdesk role
  won't do it.
- **Wait/verify instead of force:** poll `onPremisesLastSyncDateTime` (and re-read the changed attribute) so
  the UI can show "synced ✓" without any server access. This is the safe default when force isn't available.
- **Cadence to show the operator:** Connect ~30 min default; Cloud Sync ~10–20 min for an object change to
  land (the "every 2 min" figure is the scheduler cycle, not the per-object SLA).

---

## 6. SOA converter page (optional)

This is exactly the "SOA converter" idea — and it's a **real Microsoft feature**, not a hack.

- **What it is:** flip one object's authority to the cloud via `PATCH …/onPremisesSyncBehavior {isCloudManaged:true}`.
  After conversion `onPremisesSyncEnabled→null`, the object shows Source = *Cloud*, becomes fully cloud-editable,
  and Connect logs **Event ID 6956** for it.
- **Maturity (load-bearing):** **Group SOA = GA** (since Oct 2025). **User/Contact SOA = Public Preview.**
  Build the **group** path first on `/v1.0` via `Invoke-MgGraphRequest`; put user/contact behind an explicit
  **"Preview"** switch. Avoid the beta SDK cmdlets.
- **Scopes/role:** `Group-OnPremisesSyncBehavior.ReadWrite.All` (+ `User-`/`Contacts-` variants), least-priv
  role **Hybrid Administrator**; consent granted by an Application/Cloud Application Administrator. Pre-flight a
  consent check and fail clearly if missing.
- **Guardrails (must-have):**
  1. Only offer objects where `onPremisesSyncEnabled=true`.
  2. **Two-phase completion:** the PATCH alone doesn't finish it — a Connect/Cloud Sync cycle must run. The UI
     must say so and link the verification (Event 6956 / audit "Change Source of Authority from AD to cloud").
  3. **No recursion** — nested groups aren't converted with the parent; convert lowest-first.
  4. **Rollback caveats:** remove cloud-only members / access-package refs first; **User/Contact rollback** also
     requires toggling the tenant flag `blockCloudObjectTakeoverThroughHardMatchEnabled`
     (`/beta/directory/onPremisesSynchronization/{id}`) off then **back on** (easy to forget).
  5. **Mail-enabled groups/DLs:** can be SOA-converted but then aren't Graph/portal-manageable — they stay
     Exchange-only. Extension attributes 1–15 are **lost** on a converted security group. Warn loudly.
- **Do NOT conflate with OU-exclusion.** Removing an OU from sync scope **DELETES** those objects from Entra on
  the next cycle (gated by the 500-object accidental-deletion threshold) — it does *not* make them cloud-only.
  If the tool ever surfaces de-scoping, it must be labeled "cloud-delete," distinct from SOA conversion.
- **Devices:** unsupported (only user/group/orgContact). Don't offer it.

---

## 7. UX changes to existing tabs

- **Source badge** on every loaded object: `☁ Cloud` / `⛓ Synced from AD (DOMAIN)` / `☁ Cloud-managed (SOA)`.
- **Per-field affordance:** on-prem-mastered fields render read-only with an inline "managed in Active
  Directory" hint *unless* the on-prem write path is available — then they're editable and the Save splits
  cloud vs AD writes, reporting both outcomes.
- **Synced groups:** disable cloud member add/remove + nesting; offer "manage membership in AD" instead.
- **Password reset:** if synced and no SSPR writeback, warn that a cloud reset won't reach AD — offer the AD
  reset path.
- **Hybrid status panel** (small, in the top bar or a Settings section): tenant hybrid? engine? DC reachable?
  RSAT present? last sync time + a **Force sync / Refresh** button.
- **Optional Hybrid/SOA tab** for the converter, gated + clearly labeled GA-vs-Preview.

---

## 8. Module / file additions (consistent with current structure)

```
Private/
  HybridDetection.ps1   # tenant hybrid?, capability detection, per-object SOA read (onPremisesSyncEnabled/isCloudManaged)
  OnPremAd.ps1          # DC discovery, RSAT-or-LDAP abstraction, cloud->AD object mapping, Set-AD* edits
  SyncControl.ps1       # detect engine; force (Connect/Cloud); poll onPremisesLastSyncDateTime
  SoaConversion.ps1     # /v1.0 onPremisesSyncBehavior PATCH/GET, guardrails, pre-checks (group GA / user preview)
  UiHybridStatus.ps1    # status panel + force-sync button + source badges
  UiSoaTab.ps1          # optional converter page (gated)
Data/AttributeCatalog.psd1  # + Authority + AdLdapName per attribute
Configuration.ps1            # + Hybrid config: { Enabled; SyncServer; ForceMethod; AdCredentialMode; PreviewSoa }
```
The field factory (`UiFieldFactory.ps1`) gains an SOA-aware editable/read-only decision; the save paths in
`UiMainForm.ps1` gain a cloud-vs-AD split. Everything else is new, isolated files — low blast radius.

---

## 9. Groups & hybrid Exchange specifics

- **Synced security groups:** membership/displayName/description are on-prem-mastered → edit in AD, sync up.
- **DLs / mail-enabled groups in hybrid:** mastered in **on-prem Exchange** and synced; managed via on-prem
  Exchange (EAC/Exchange Management Shell), **not** EXO, until modernized/SOA-moved.
- **Mailboxes in hybrid:** these are **remote mailboxes** — the on-prem object (`New-/Enable-RemoteMailbox`)
  points at a mailbox that lives in EXO. The existing Exchange tab must **check the object's mastering** before
  assuming Exchange Online is authoritative; for a synced recipient, identity attributes still flow from AD.

---

## 10. Phased rollout (MVP-first)

- **Phase 0 — Awareness (MVP, low risk, high value):** hybrid + per-object SOA detection, source badges,
  pre-gating of blocked cloud edits with clear "managed in AD" messaging. *No on-prem writes yet* — this alone
  stops the confusing silent-failure UX. Pure Graph, ships fast.
- **Phase 1 — On-prem edit:** DC discovery + RSAT/LDAP write path for synced **users** (attributes,
  enable/disable, password, group membership), with capability gating and cloud↔AD save split.
- **Phase 2 — Sync control:** engine detection, force-sync (Connect local/remote, Cloud restart/on-demand),
  and poll-for-landed so edits "appear" promptly.
- **Phase 3 — SOA converter:** GA **group** conversion first; user/contact behind a Preview flag; full
  guardrails + two-phase UX.
- **Phase 4 — Hybrid Exchange:** remote-mailbox / on-prem-mastered DL awareness in the Exchange tab.

Each phase is independently shippable and useful; you can stop after any of them.

---

## 11. Risks & guardrails

- **Production AD writes** — the tool would mutate live AD. Needs writable-DC line-of-sight + delegated rights;
  RODC rejects writes; keep the same typed-confirm guards used for soft-delete.
- **Two separate trust planes** — Graph scopes get you nowhere in AD and vice-versa; the UI must make the
  active backend obvious so an operator never thinks an AD edit "didn't take" when it's actually pending sync.
- **SOA is consequential and audited** — two-phase, partially preview (users), and irreversible-ish if cloud
  state accrues before rollback. Gate hard; default to groups-only.
- **OU-exclusion = delete** — never expose it as "make cloud-only."
- **Don't regress the cloud-only path** — all of this is dormant unless hybrid is detected; the existing
  offline harness + closure lint must stay green, and new on-prem code paths get their own dependency-free
  unit seams (mock the AD/Graph calls).

---

## 12. Open questions (need your input before building)

1. **Sync engine(s)** across your tenants — Entra **Connect Sync**, **Cloud Sync**, or a mix? (Decides the
   force-sync implementation; Cloud Sync gives a clean Graph path, Connect needs the sync server.)
2. **Workstation reality** — do the helpdesk machines have the **RSAT AD module** and line-of-sight to a
   **writable DC**, and do the techs hold **delegated AD rights**? Or should I lead with the LDAP fallback and
   a prompted AD credential?
3. **Force sync vs wait** — is the sync server reachable over **WinRM** for a forced cycle, or should the tool
   trigger Cloud Sync via Graph / just show "wait for next sync" with a refresh?
4. **SOA scope** — do you actually want to *perform* conversions, or is read-only SOA awareness (Phase 0)
   enough for now? If converting: **groups-only (GA)** to start, users left as preview/off?
5. **Passwords for synced users** — is **SSPR password writeback** configured, or should resets always go
   straight to AD?
6. **AD credential model** — reuse the signed-in Windows identity, or prompt for a dedicated AD-admin
   credential per session?

---

## Decisions locked (2026-06-13)

1. **Connect Sync only** (no Cloud Sync). → Auto-detect that the tenant is Connect-Sync hybrid; **drop the
   Cloud-Sync force/on-demand path** entirely for now. Sync server: best-effort auto-suggest the hostname, but
   provide a **saved manual override** in config (used for WinRM).
2. **RSAT: detect, and auto-install if missing** (`Add-WindowsCapability`, needs elevation). On-prem features
   gate on **DC line-of-sight**; the **cloud side runs anywhere**. Techs hold rights for both planes.
3. **Sync server is WinRM-reachable** → force a delta via
   `Invoke-Command -ComputerName $SyncServer { Start-ADSyncSyncCycle -PolicyType Delta }`.
4. **Group SOA only — perform conversions.** Build the GA group converter (`/v1.0`); **user/contact SOA is
   omitted** (no preview toggle needed for now).
5. **Synced-user password resets route to AD** (`Set-ADAccountPassword`); cloud-only users reset in the cloud.
   (User uses SSPR for *self-service* writeback but hasn't verified that an *admin* cloud reset writes back, and
   prefers on-prem-where-possible — so the tool resets synced users on-prem rather than relying on writeback.
   One-line catalog flip of `passwordProfile` to `Authority='Cloud'` if cloud admin-reset+writeback is confirmed.)
6. **AD credential: reuse the signed-in Windows identity** (integrated auth) by default; **prompt for a
   credential only** if an AD edit is attempted and integrated auth isn't usable / nothing is detected.

**Net design simplifications from the above:** §5 collapses to Connect-Sync force-via-WinRM + poll
`onPremisesLastSyncDateTime`; §6 converter is groups-only; password handling stays as-is (writeback);
on-prem access uses the current Kerberos context (no credential store).

