# Contributing

N-API-P welcomes focused issues, documentation fixes, tests, and pull requests.

## Before Opening a Pull Request

1. Search existing issues and pull requests.
2. Keep the change focused on one problem.
3. Do not include real credentials, employee data, prompts, responses, database
   dumps, or internal deployment records.
4. Add or update tests when behavior changes.
5. Run the relevant local checks before submitting.

## Useful Checks

Backend:

```powershell
Set-Location .\backend
go test ./...
go vet ./...
go build -o ..\n-api-p.exe .\cmd\n-api-p
```

Frontend:

```powershell
Set-Location .\frontend
npm ci --ignore-scripts
npm run verify
```

Demonstration stack:

```powershell
.\local-demo\start.ps1
.\local-demo\stop.ps1
```

The local demo uses synthetic data only.

## Pull Request Description

Include:

- The problem being solved
- The behavior before and after the change
- Security or migration implications
- Commands run and their results
- Remaining limitations or unverified scenarios

## Security

Follow [SECURITY.md](SECURITY.md). Never disclose a vulnerability or secret in a
public issue.

## License

By contributing, you agree that your contribution is licensed under the
repository's MIT License.
