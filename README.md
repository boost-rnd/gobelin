# gobelin 🧵

A command-line tool to scan your Go project's dependencies for potential repojacking vulnerabilities.

> **About the name:** "Gobelin" refers to the [Gobelins Manufactory](https://en.wikipedia.org/wiki/Gobelins_Manufactory), the prestigious French royal tapestry workshop established in Paris. Just as the Gobelins wove intricate tapestries, `gobelin` untangles the complex web of your **Go** dependencies to reveal hidden threats. (Yes, it's also a pun on Go and goblins—those sneaky creatures that hijack your dependencies when you're not looking!)

## What is Repojacking? ⚠️

Repojacking occurs when a GitHub account (user or organization) that owns a repository gets deleted or renamed. An attacker can then register that username and create a repository with the same name, effectively hijacking any projects that depend on it. Your project might unknowingly pull malicious code during builds or updates.

`gobelin` helps you identify vulnerable dependencies before they're exploited by checking if the GitHub account owners of your dependencies still exist.

**Learn more:** Read our comprehensive research on Go Modules supply chain security threats: [Don't Go with the Flaw](https://boostsecurity.io/blog/dont-go-with-the-flaw)

## Features ✨
* Uses the built-in `go list -m all` command to get a list of all dependencies.

* Handles GitHub API rate limits with automatic retry logic.

* Use a GitHub API token (`-t`, `--token`) to increase your rate limit for large projects.

* Can output a full JSON report (`-o`, `--output`) for processing in automated pipelines.

* Provides a clean, colorful summary to the terminal, showing only the hijackable repositories found.

## Installation 📦

### From Source

```bash
go install boost-rnd/gobelin@latest
```

### Running Locally

```bash
git clone https://github.com/your-org/gobelin.git
cd gobelin
go run . scan [options]
```

## Usage 🚀

```bash
gobelin scan [path-to-project-root] [flags]
```

### Flags
```
Flag	Shorthand	Description
--token	-t	GitHub API token (optional). Auto-detected from GH_TOKEN, GITHUB_TOKEN env vars, or 'gh auth token'.
--format	-f	Output format: text (default) or json. Use json for machine-readable output.
--output	-o	Output file to write results. If not set, prints to stdout. Works with both text and json formats.
--verbose	-v	Enable verbose output with detailed debug information and timestamps.
--help	-h	Show help message.
```

**Note:** `gobelin` automatically detects your GitHub token from:
1. `GH_TOKEN` environment variable
2. `GITHUB_TOKEN` environment variable (common in CI)
3. `gh auth token` command (if GitHub CLI is installed)

This helps avoid rate limiting. You can also explicitly provide a token with `--token`.

## Examples 💡

### Scan the current directory

```bash
gobelin scan
```

### Scan a specific project

Running the scan on a project with all accounts active:

```bash
gobelin scan poutine/
```

```
Scan Results

✓ SUCCESS All GitHub accounts are registered and active!
```

Running the scan on a project with a missing account:

```bash
gobelin scan go_replace_vuln/
```

```
Scan Results

⚠ REPOJACKING DANGER Found 1 missing GitHub account(s):

  ⚠ GitHub account NOT found: quark-engine (package: github.com/quark-engine/quark-engine, status: 404)
```

### Output JSON to stdout

```bash
gobelin scan --format json
```

### Save results to a file

```bash
# Save as JSON
gobelin scan -o report.json --format json

# Save as text
gobelin scan -o report.txt
```

### Enable verbose/debug output

```bash
gobelin scan --verbose
```

### Scan from a package list file

If you want to verify a specific list of packages, you can provide a text or markdown file with one package per line. `gobelin` will verify only those packages without generating an SBOM.

```bash
gobelin scan packages.txt
```

The packages must be identified with the `github.com` prefix (one per line). You can specify just the GitHub account or include the full repository path.

Example `packages.txt`:
```
github.com/spf13/cobra
github.com/fatih/color
github.com/stretchr
```

## How It Works 🔍

- Analyzes your `go.mod` file using `go list -m all` to identify all direct and transitive dependencies
- Extracts GitHub-hosted packages from the dependency list
- Checks each unique GitHub account owner via the GitHub API
- Handles rate limits gracefully with automatic retry logic
- Respects `replace` directives in `go.mod` (tests the replacement module, not the original)
- Reports any missing or deleted GitHub accounts

## Limitations ⚡

- Currently only supports GitHub-hosted packages (GitLab, Bitbucket, and other platforms are not yet supported)
- Checks account existence only (does not verify repository existence or detect repository transfers)
- Requires network access to the GitHub API

## License 📜

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the [LICENSE](LICENSE) file for details.

## Contributing 🤝

Contributions are welcome! Please feel free to submit issues or pull requests.
