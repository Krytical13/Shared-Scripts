# Shared Scripts

A collection of PowerShell scripts I've written while working on Microsoft identity, directory, and messaging systems. Sharing them in case they save someone else a few hours.

Each script is standalone — no module install, no shared helpers. Drop the `.ps1` file somewhere and run it.

---

## Layout

Scripts are organized into folders by the system they primarily touch:

```
.
├── AD/          — on-prem Active Directory
├── Entra/       — Microsoft Entra ID (cloud identity)
├── Exchange/    — Exchange Online / on-prem Exchange
├── Mixed/       — hybrid / multi-system scripts that don't fit cleanly above
└── ...
```

Folder names are self-explanatory. Browse the one that matches what you're trying to do.

---

## Finding what you need

Every script has full [comment-based help](https://learn.microsoft.com/powershell/scripting/developer/help/writing-comment-based-help-topics) — synopsis, description, parameters, examples, and notes. To inspect any script without running it:

```powershell
Get-Help .\Path\To\Script-Name.ps1 -Full
```

That's the authoritative source for what a script does, what it needs, and how to invoke it.

---

## Prerequisites (general)

- **Windows PowerShell 5.1** or **PowerShell 7.x** (per-script minimums declared via `#Requires`)
- Whatever modules and Graph/Exchange/AD permissions a given script needs — listed in its `.NOTES` block
- An account with the right roles for the system being touched

Scripts won't fail silently — if a module or scope is missing, you'll get a clear error with an install or consent hint.

---

## Quick start

```powershell
# Clone or download the repo, then pick a script and read its help:
Get-Help .\Entra\Some-Script.ps1 -Full

# Run it:
.\Entra\Some-Script.ps1
```

Most scripts default their output to `$env:USERPROFILE\Documents\<Something>\` and accept a `-LogPath` parameter if you want to redirect.

---

## License

[MIT](./LICENSE) — use, modify, and redistribute freely. No warranty.

---

## Disclaimer

These scripts touch production identity, directory, and messaging systems. **Test in a non-production environment first.** Read the `.NOTES` block of each script for its specific caveats and required permissions.

Not affiliated with or endorsed by Microsoft. Shared as-is on my own time.

---

## AI assistance

Portions of these scripts were drafted with AI assistance and then reviewed, tested, and edited by me in real environments. I'm the one responsible for what's in here. Same expectation applies to anyone running them: **understand and test before running**.

---

## Issues & contributions

- **Bug reports:** open an issue with what you ran, what you expected, what happened, and your PowerShell/module versions.
- **Suggestions / PRs:** welcome for small fixes. For larger changes, open an issue first so we can discuss the approach.
- **No guarantee of response time** — this is a side project, not a product.
