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
