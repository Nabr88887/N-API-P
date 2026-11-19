# Architecture Assets

- `n-api-p-architecture.json` is the Archify source specification.
- `n-api-p-architecture.html` is the validated interactive diagram.
- `social-preview.png` is generated from the Archify share-card export.

Validate after changing the source:

```powershell
node path\to\archify\bin\archify.mjs validate architecture `
  .\docs\assets\n-api-p-architecture.json `
  --quality showcase `
  --repo-root . `
  --json
```

Regenerate the interactive artifact:

```powershell
node path\to\archify\bin\archify.mjs deliver architecture `
  .\docs\assets\n-api-p-architecture.json `
  .\docs\assets\n-api-p-architecture.html `
  --quality showcase `
  --repo-root . `
  --json
```

Use the viewer's **Export → Share card** action to refresh
`social-preview.png`.
