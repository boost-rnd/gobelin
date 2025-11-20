// gobelin - Go Repojacking Scanner
// Copyright (C) 2025 boostsecurity.io Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type Package struct {
	Path    string
	Version string
	Owner   string
	Repo    string
}

type SBOMModule struct {
	Path    string      `json:"Path"`
	Version string      `json:"Version"`
	Replace *SBOMModule `json:"Replace,omitempty"` // Handles replace directives
}

var (
	githubToken string
	outputFile  string
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [path-to-project-or-package-list]",
	Short: "Scan your project to find hijackable dependencies",
	Long: `Scan analyzes Go project dependencies for potential repojacking vulnerabilities.

It checks if GitHub account owners of your dependencies still exist. If an account
has been deleted, an attacker could register that username and publish malicious code.

You can scan:
  - A project directory (analyzes go.mod with 'go list -m all')
  - A text/markdown file with a list of packages to verify (one per line)`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return ScanProject(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

// detectGitHubToken attempts to auto-detect a GitHub token from environment or gh CLI
func detectGitHubToken() string {
	// Try GH_TOKEN environment variable first
	if token := os.Getenv("GH_TOKEN"); token != "" {
		if verbose {
			fmt.Fprintf(os.Stderr, "→ Using GitHub token from GH_TOKEN\n")
		}
		return token
	}

	// Try GITHUB_TOKEN environment variable (common in CI)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		if verbose {
			fmt.Fprintf(os.Stderr, "→ Using GitHub token from GITHUB_TOKEN\n")
		}
		return token
	}

	// Try gh CLI auth token
	cmd := exec.Command("gh", "auth", "token")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		token := strings.TrimSpace(string(output))
		if token != "" {
			if verbose {
				fmt.Fprintf(os.Stderr, "→ Using GitHub token from 'gh auth token'\n")
			}
			return token
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "→ No GitHub token found, proceeding without authentication\n")
	}
	return ""
}

func ScanProject(cmd *cobra.Command, args []string) error {
	// Auto-detect GitHub token if not provided
	if githubToken == "" {
		githubToken = detectGitHubToken()
	}

	projectPath := "."
	isDir := true // Default to directory scan
	var err error

	if len(args) > 0 {
		projectPath = args[0]
		isDir, projectPath, err = analyseFilePath(projectPath)
		if err != nil {
			return fmt.Errorf("unsupported file: %w", err)
		}
	}

	var packages []Package
	if isDir {
		// Show simple message for text output, verbose log for debug
		if verbose {
			fmt.Fprintf(os.Stderr, "→ Generating SBOM with `go list -m all`... (project: %s)\n", projectPath)
		} else if outputFormat == "text" {
			fmt.Printf("Generating SBOM with `go list -m all`...\n")
		}

		// Generate SBOM
		sbom, err := generateSBOM(projectPath)
		if err != nil {
			return fmt.Errorf("failed to generate SBOM: %w", err)
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "→ SBOM generated: %d packages\n", len(sbom))
		} else if outputFormat == "text" {
			fmt.Printf("Found %d packages\n", len(sbom))
		}

		// Extract packages
		packages = extractPackages(sbom)

	} else {
		if verbose {
			fmt.Fprintf(os.Stderr, "→ Reading package list from %s\n", projectPath)
		} else if outputFormat == "text" {
			fmt.Printf("Reading package list from file...\n")
		}

		packages, err = readPackagesFromFile(projectPath)
		if err != nil {
			return fmt.Errorf("failed to read packages from file: %w", err)
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "→ Loaded %d packages from file\n", len(packages))
		} else if outputFormat == "text" {
			fmt.Printf("Loaded %d packages\n", len(packages))
		}
	}

	uniqueAccounts := countUniqueOwners(packages)
	if verbose {
		fmt.Fprintf(os.Stderr, "→ Checking %d unique GitHub accounts...\n", uniqueAccounts)
	} else if outputFormat == "text" {
		fmt.Printf("Checking %d unique GitHub accounts...\n", uniqueAccounts)
	}

	// Check GitHub accounts
	results := checkGitHubAccounts(packages)

	// Output results
	return outputResults(results)

}

func countUniqueOwners(packages []Package) int {
	owners := make(map[string]bool)
	for _, pkg := range packages {
		owners[pkg.Owner] = true
	}
	return len(owners)
}

func analyseFilePath(projectPath string) (bool, string, error) {
	info, err := os.Stat(projectPath)
	if err != nil {
		return false, "", fmt.Errorf("failed to analyse project path: %w", err)
	}

	var isDir bool
	supportedFileExts := map[string]bool{
		".txt": true,
		".md":  true,
	}

	if info.IsDir() {
		if verbose {
			fmt.Fprintf(os.Stderr, "→ Analyzing directory: %s\n", projectPath)
		}
		isDir = true
	} else {
		ext := filepath.Ext(projectPath)
		if ext == ".mod" {
			projectPath = filepath.Dir(projectPath)
			isDir = true
		} else if supportedFileExts[ext] {
			isDir = false
			if verbose {
				fmt.Fprintf(os.Stderr, "→ Reading package list from file\n")
			}
		} else {
			return false, "", fmt.Errorf("unsupported file type: %s", ext)
		}
	}
	return isDir, projectPath, nil
}

func generateSBOM(projectPath string) ([]SBOMModule, error) {
	// Use go list to get module information
	cmd := exec.Command("go", "list", "-json", "-m", "all")
	cmd.Dir = projectPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go list failed: %w\nOutput: %s", err, string(output))
	}

	// Parse JSON stream (go list outputs multiple JSON objects)
	var modules []SBOMModule
	decoder := json.NewDecoder(strings.NewReader(string(output)))

	for decoder.More() {
		var module SBOMModule
		if err := decoder.Decode(&module); err != nil {
			continue
		}
		modules = append(modules, module)
	}

	return modules, nil

}

func extractPackages(sbom []SBOMModule) []Package {
	packages := make([]Package, 0, len(sbom))

	for _, module := range sbom {

		// Use the replacement module if it exists
		actualModule := module
		if module.Replace != nil {
			actualModule = *module.Replace
		}

		// Extract GitHub owner and repo
		owner, repo := parseGitHubPath(actualModule.Path)
		if owner == "" {
			continue
		}

		packages = append(packages, Package{
			Path:    actualModule.Path,
			Version: actualModule.Version,
			Owner:   owner,
			Repo:    repo,
		})
	}

	return packages
}

func readPackagesFromFile(filePath string) ([]Package, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var packages []Package
	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// Normalize the package path
		packagePath := line

		// Extract owner and repo
		owner, repo := parseGitHubPath(packagePath)
		if owner == "" {
			if verbose {
				fmt.Fprintf(os.Stderr, "⚠ Could not parse GitHub path (line %d: %s)\n", lineNumber, line)
			}
			continue
		}

		packages = append(packages, Package{
			Path:    packagePath,
			Version: "", // Version unknown for file-based packages
			Owner:   owner,
			Repo:    repo,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if len(packages) == 0 {
		return nil, errors.New("no valid packages found in file")
	}

	return packages, nil
}

func parseGitHubPath(path string) (owner, repo string) {
	// Handle github.com paths
	if strings.HasPrefix(path, "github.com/") {
		parts := strings.Split(path, "/")
		if len(parts) >= 3 {
			owner = parts[1]
			repo = parts[2]
			return
			// Ok if just the owner
		} else if len(parts) >= 2 {
			owner = parts[1]
			repo = ""
			return
		}
	}

	return "", ""
}

func checkGitHubAccounts(packages []Package) []map[string]interface{} {
	client := &http.Client{Timeout: 10 * time.Second}
	results := make([]map[string]interface{}, 0, len(packages))
	checkedOwners := make(map[string]bool)

	if githubToken != "" && verbose {
		fmt.Fprintf(os.Stderr, "→ Using provided GitHub token\n")
	}

	for _, pkg := range packages {
		// Skip if we already checked this owner
		if checkedOwners[pkg.Owner] {
			continue
		}

		exists, statusCode, resetTime := checkGitHubUser(client, pkg.Owner)

		result := map[string]interface{}{
			"owner":       pkg.Owner,
			"exists":      exists,
			"status_code": statusCode,
			"package":     pkg.Path,
		}

		if exists {
			if verbose {
				fmt.Fprintf(os.Stderr, "  ✓ %s\n", pkg.Owner)
			}
		} else if statusCode == 403 || statusCode == 429 {
			if verbose {
				fmt.Fprintf(os.Stderr, "  ⚠ %s (rate limited, status: %d)\n", pkg.Owner, statusCode)
			}
			result["rate_limited"] = true

			// Sleep until rate limit resets
			if !resetTime.IsZero() && resetTime.After(time.Now()) {
				sleepDuration := time.Until(resetTime)
				if verbose {
					fmt.Fprintf(os.Stderr, "  ⏳ Sleeping for %v until rate limit resets...\n", sleepDuration.Round(time.Second))
				}
				time.Sleep(sleepDuration)
			} else {
				// Default sleep if we can't parse reset time
				if verbose {
					fmt.Fprintf(os.Stderr, "  ⏳ Sleeping for 60 seconds...\n")
				}
				time.Sleep(60 * time.Second)
			}

			// Retry the request
			if verbose {
				fmt.Fprintf(os.Stderr, "  ↻ Retrying %s...\n", pkg.Owner)
			}
			exists, statusCode, _ = checkGitHubUser(client, pkg.Owner)
			result["exists"] = exists
			result["status_code"] = statusCode

			if exists {
				if verbose {
					fmt.Fprintf(os.Stderr, "  ✓ %s (after retry)\n", pkg.Owner)
				}
			} else {
				if verbose {
					fmt.Fprintf(os.Stderr, "  ✗ %s NOT FOUND (status: %d)\n", pkg.Owner, statusCode)
				}
			}
		} else {
			if verbose {
				fmt.Fprintf(os.Stderr, "  ✗ %s NOT FOUND (status: %d)\n", pkg.Owner, statusCode)
			}
		}

		results = append(results, result)
		checkedOwners[pkg.Owner] = true
	}

	return results
}

func checkGitHubUser(client *http.Client, owner string) (exists bool, statusCode int, resetTime time.Time) {
	url := "https://api.github.com/users/" + owner

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, 0, time.Time{}
	}

	// Add token if provided
	if githubToken != "" {
		req.Header.Set("Authorization", "Bearer "+githubToken)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return false, 0, time.Time{}
	}
	defer resp.Body.Close()

	// Parse rate limit reset time if we hit the limit
	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		if resetHeader := resp.Header.Get("X-RateLimit-Reset"); resetHeader != "" {
			if resetUnix, err := strconv.ParseInt(resetHeader, 10, 64); err == nil {
				resetTime = time.Unix(resetUnix, 0)
			}
		}
	}

	return resp.StatusCode == 200, resp.StatusCode, resetTime

}

func outputResults(results []map[string]interface{}) error {
	// Prepare JSON output if needed
	var jsonOutput []byte
	var err error

	if outputFormat == "json" || outputFile != "" {
		jsonOutput, err = json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal results: %w", err)
		}
	}

	// Write to file if specified
	if outputFile != "" {
		err = os.WriteFile(outputFile, jsonOutput, 0644)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "→ Results written to file: %s\n", outputFile)
		}

		// If format is not explicitly JSON, also show text summary
		if outputFormat != "json" {
			printTextResults(results)
		}
		return nil
	}

	// Output to stdout based on format
	if outputFormat == "json" {
		fmt.Println(string(jsonOutput))
	} else {
		printTextResults(results)
	}

	return nil
}

func printTextResults(results []map[string]interface{}) {
	var missingAccounts []map[string]interface{}

	for _, r := range results {
		exists, _ := r["exists"].(bool)
		if !exists {
			missingAccounts = append(missingAccounts, r)
		}
	}

	// In verbose mode, log the summary consistently
	if verbose {
		fmt.Fprintf(os.Stderr, "→ Scan complete\n")
		if len(missingAccounts) == 0 {
			fmt.Fprintf(os.Stderr, "→ All GitHub accounts are registered and active (%d checked)\n", len(results))
		} else {
			fmt.Fprintf(os.Stderr, "⚠ Found missing GitHub accounts - REPOJACKING DANGER! (%d missing)\n", len(missingAccounts))
			for _, r := range missingAccounts {
				owner, _ := r["owner"].(string)
				pkg, _ := r["package"].(string)
				statusCode, _ := r["status_code"].(int)
				fmt.Fprintf(os.Stderr, "  ✗ GitHub account NOT FOUND: %s (package: %s, status: %d)\n", owner, pkg, statusCode)
			}
		}
		return
	}

	// Pretty format for non-verbose text mode
	// Print header
	fmt.Println()
	fmt.Println("Scan Results")
	fmt.Println()

	// Print summary
	if len(missingAccounts) == 0 {
		fmt.Printf("✓ SUCCESS All GitHub accounts are registered and active!\n")
	} else {
		fmt.Printf("⚠ REPOJACKING DANGER Found %d missing GitHub account(s):\n\n", len(missingAccounts))

		for _, r := range missingAccounts {
			pkg, _ := r["package"].(string)
			owner, _ := r["owner"].(string)
			statusCode, _ := r["status_code"].(int)

			fmt.Printf("  ✗ NOT FOUND: GitHub account %s (package: %s, status: %d)\n", owner, pkg, statusCode)
		}
	}

	fmt.Println()
}
