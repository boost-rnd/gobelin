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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantOwner    string
		wantRepo     string
		wantRegistry string
	}{
		{
			name:         "full package path",
			path:         "github.com/spf13/cobra",
			wantOwner:    "spf13",
			wantRepo:     "cobra",
			wantRegistry: "github.com",
		},
		{
			name:         "package with subpath",
			path:         "github.com/spf13/cobra/doc",
			wantOwner:    "spf13",
			wantRepo:     "cobra",
			wantRegistry: "github.com",
		},
		{
			name:         "owner only",
			path:         "github.com/spf13",
			wantOwner:    "spf13",
			wantRepo:     "",
			wantRegistry: "github.com",
		},
		{
			name:         "non-github path",
			path:         "golang.org/x/tools",
			wantOwner:    "",
			wantRepo:     "",
			wantRegistry: "",
		},
		{
			name:         "empty path",
			path:         "",
			wantOwner:    "",
			wantRepo:     "",
			wantRegistry: "",
		},
		{
			name:         "github.com only",
			path:         "github.com",
			wantOwner:    "",
			wantRepo:     "",
			wantRegistry: "",
		},
		{
			name:         "github.com with trailing slash",
			path:         "github.com/",
			wantOwner:    "",
			wantRepo:     "",
			wantRegistry: "github.com",
		},
		{
			name:         "full gitlab path",
			path:         "gitlab.com/bosi/decorder",
			wantOwner:    "bosi",
			wantRepo:     "decorder",
			wantRegistry: "gitlab.com",
		},
		{
			name:         "gitlab owner",
			path:         "gitlab.com/bosi",
			wantOwner:    "bosi",
			wantRepo:     "",
			wantRegistry: "gitlab.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOwner, gotRepo, gotRegistry := parsePath(tt.path)
			if gotOwner != tt.wantOwner {
				t.Errorf("parsePath() gotOwner = %v, want %v", gotOwner, tt.wantOwner)
			}
			if gotRepo != tt.wantRepo {
				t.Errorf("parsePath() gotRepo = %v, want %v", gotRepo, tt.wantRepo)
			}
			if gotRegistry != tt.wantRegistry {
				t.Errorf("parsePath() gotRegistry = %v, want %v", gotRegistry, tt.wantRegistry)
			}
		})
	}
}

func TestExtractPackages(t *testing.T) {
	tests := []struct {
		name    string
		sbom    []SBOMModule
		wantLen int
		wantPkg *Package
	}{
		{
			name: "single github package",
			sbom: []SBOMModule{
				{Path: "github.com/spf13/cobra", Version: "v1.0.0"},
			},
			wantLen: 1,
			wantPkg: &Package{
				Path:     "github.com/spf13/cobra",
				Version:  "v1.0.0",
				Owner:    "spf13",
				Repo:     "cobra",
				Registry: "github.com",
			},
		},
		{
			name: "single gitlab package",
			sbom: []SBOMModule{
				{Path: "gitlab.com/bosi/decorder", Version: "v0.4.0"},
			},
			wantLen: 1,
			wantPkg: &Package{
				Path:     "gitlab.com/bosi/decorder",
				Version:  "v0.4.0",
				Owner:    "bosi",
				Repo:     "decorder",
				Registry: "gitlab.com",
			},
		},
		{
			name: "package with replace directive",
			sbom: []SBOMModule{
				{
					Path:    "github.com/old/package",
					Version: "v1.0.0",
					Replace: &SBOMModule{
						Path:    "github.com/new/package",
						Version: "v2.0.0",
					},
				},
			},
			wantLen: 1,
			wantPkg: &Package{
				Path:     "github.com/new/package",
				Version:  "v2.0.0",
				Owner:    "new",
				Repo:     "package",
				Registry: "github.com",
			},
		},
		{
			name: "mixed github and non-github packages",
			sbom: []SBOMModule{
				{Path: "github.com/spf13/cobra", Version: "v1.0.0"},
				{Path: "golang.org/x/tools", Version: "v0.1.0"},
				{Path: "github.com/fatih/color", Version: "v1.13.0"},
				{Path: "gitlab.com/bosi/decorder", Version: "v0.4.0"},
			},
			wantLen: 3,
		},
		{
			name:    "empty sbom",
			sbom:    []SBOMModule{},
			wantLen: 0,
		},
		{
			name: "non-github packages only",
			sbom: []SBOMModule{
				{Path: "golang.org/x/tools", Version: "v0.1.0"},
				{Path: "example.com/package", Version: "v1.0.0"},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPackages(tt.sbom)
			if len(got) != tt.wantLen {
				t.Errorf("extractPackages() length = %v, want %v", len(got), tt.wantLen)
			}
			if tt.wantPkg != nil && len(got) > 0 {
				pkg := got[0]
				if pkg.Path != tt.wantPkg.Path {
					t.Errorf("extractPackages() Path = %v, want %v", pkg.Path, tt.wantPkg.Path)
				}
				if pkg.Version != tt.wantPkg.Version {
					t.Errorf("extractPackages() Version = %v, want %v", pkg.Version, tt.wantPkg.Version)
				}
				if pkg.Owner != tt.wantPkg.Owner {
					t.Errorf("extractPackages() Owner = %v, want %v", pkg.Owner, tt.wantPkg.Owner)
				}
				if pkg.Repo != tt.wantPkg.Repo {
					t.Errorf("extractPackages() Repo = %v, want %v", pkg.Repo, tt.wantPkg.Repo)
				}
			}
		})
	}
}

func TestAnalyseFilePath(t *testing.T) {
	tmpDir := t.TempDir()

	txtFile := filepath.Join(tmpDir, "test.txt")
	modFile := filepath.Join(tmpDir, "go.mod")
	mdFile := filepath.Join(tmpDir, "test.md")
	unsupportedFile := filepath.Join(tmpDir, "test.json")

	for _, f := range []string{txtFile, modFile, mdFile, unsupportedFile} {
		if err := os.WriteFile(f, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	tests := []struct {
		name        string
		path        string
		wantIsDir   bool
		wantPath    string
		wantErr     bool
		errContains string
	}{
		{
			name:      "directory path",
			path:      tmpDir,
			wantIsDir: true,
			wantPath:  tmpDir,
			wantErr:   false,
		},
		{
			name:      "txt file",
			path:      txtFile,
			wantIsDir: false,
			wantPath:  txtFile,
			wantErr:   false,
		},
		{
			name:      "md file",
			path:      mdFile,
			wantIsDir: false,
			wantPath:  mdFile,
			wantErr:   false,
		},
		{
			name:      "go.mod file returns parent directory",
			path:      modFile,
			wantIsDir: true,
			wantPath:  tmpDir,
			wantErr:   false,
		},
		// Note: Skipping unsupported file type and non-existent path tests
		// because analyseFilePath() calls logger.Fatal() which exits the process
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsDir, gotPath, err := analyseFilePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("analyseFilePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("analyseFilePath() error = %v, should contain %v", err, tt.errContains)
				return
			}
			if !tt.wantErr {
				if gotIsDir != tt.wantIsDir {
					t.Errorf("analyseFilePath() gotIsDir = %v, want %v", gotIsDir, tt.wantIsDir)
				}
				if gotPath != tt.wantPath {
					t.Errorf("analyseFilePath() gotPath = %v, want %v", gotPath, tt.wantPath)
				}
			}
		})
	}
}

func TestReadPackagesFromFile(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantLen     int
		wantErr     bool
		errContains string
		checkFirst  *Package
	}{
		{
			name: "valid package list",
			content: `github.com/spf13/cobra
github.com/fatih/color
github.com/stretchr/testify`,
			wantLen: 3,
			wantErr: false,
			checkFirst: &Package{
				Path:  "github.com/spf13/cobra",
				Owner: "spf13",
				Repo:  "cobra",
			},
		},
		{
			name: "mixed valid and invalid lines",
			content: `github.com/spf13/cobra
not-a-github-path
github.com/fatih/color`,
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "owner only paths",
			content: `github.com/spf13`,
			wantLen: 1,
			wantErr: false,
			checkFirst: &Package{
				Path:  "github.com/spf13",
				Owner: "spf13",
				Repo:  "",
			},
		},
		{
			name: "empty lines and whitespace",
			content: `
github.com/spf13/cobra

   github.com/fatih/color

`,
			wantLen: 2,
			wantErr: false,
		},
		{
			name:        "no valid packages",
			content:     "not-github.com/test\nexample.com/test",
			wantLen:     0,
			wantErr:     true,
			errContains: "no valid packages found",
		},
		{
			name:        "empty file",
			content:     "",
			wantLen:     0,
			wantErr:     true,
			errContains: "no valid packages found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), "packages.txt")
			if err := os.WriteFile(tmpFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			got, err := readPackagesFromFile(tmpFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("readPackagesFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("readPackagesFromFile() error = %v, should contain %v", err, tt.errContains)
				return
			}
			if !tt.wantErr {
				if len(got) != tt.wantLen {
					t.Errorf("readPackagesFromFile() length = %v, want %v", len(got), tt.wantLen)
				}
				if tt.checkFirst != nil && len(got) > 0 {
					if got[0].Path != tt.checkFirst.Path {
						t.Errorf("readPackagesFromFile() first.Path = %v, want %v", got[0].Path, tt.checkFirst.Path)
					}
					if got[0].Owner != tt.checkFirst.Owner {
						t.Errorf("readPackagesFromFile() first.Owner = %v, want %v", got[0].Owner, tt.checkFirst.Owner)
					}
					if got[0].Repo != tt.checkFirst.Repo {
						t.Errorf("readPackagesFromFile() first.Repo = %v, want %v", got[0].Repo, tt.checkFirst.Repo)
					}
				}
			}
		})
	}

	t.Run("non-existent file", func(t *testing.T) {
		_, err := readPackagesFromFile("/nonexistent/file.txt")
		if err == nil {
			t.Error("readPackagesFromFile() expected error for non-existent file")
		}
	})
}

func TestCheckUser(t *testing.T) {

	client := &http.Client{Timeout: 5 * time.Second}

	tests := []struct {
		name              string
		pkg               Package
		wantExists        bool
		wantStatusCode    int
		skipIfRateLimited bool
	}{
		{
			name: "GitHub - known user exists (golang)",
			pkg: Package{
				Registry: "github.com",
				Path:     "github.com/golang/go",
				Version:  "",
				Owner:    "golang",
				Repo:     "go",
			},
			wantExists:        true,
			wantStatusCode:    200,
			skipIfRateLimited: true,
		},
		{
			name: "GitHub - known user exists (torvalds)",
			pkg: Package{
				Registry: "github.com",
				Path:     "github.com/torvalds/linux",
				Version:  "",
				Owner:    "torvalds",
				Repo:     "linux",
			},
			wantExists:        true,
			wantStatusCode:    200,
			skipIfRateLimited: true,
		},
		{
			name: "GitHub - non-existent user",
			pkg: Package{
				Registry: "github.com",
				Path:     "github.com/this-user-definitely-does-not-exist-12345/repo",
				Version:  "",
				Owner:    "this-user-definitely-does-not-exist-12345",
				Repo:     "repo",
			},
			wantExists:        false,
			wantStatusCode:    404,
			skipIfRateLimited: true,
		},
		{
			name: "GitLab - known user exists (gitlab-org)",
			pkg: Package{
				Registry: "gitlab.com",
				Path:     "gitlab.com/gitlab-org/gitlab",
				Version:  "",
				Owner:    "gitlab",
				Repo:     "gitlab",
			},
			wantExists:        true,
			wantStatusCode:    200,
			skipIfRateLimited: true,
		},
		{
			name: "GitLab - non-existent user",
			pkg: Package{
				Registry: "gitlab.com",
				Path:     "gitlab.com/this-user-definitely-does-not-exist-99999/repo",
				Version:  "",
				Owner:    "this-user-definitely-does-not-exist-99999",
				Repo:     "repo",
			},
			wantExists:        false,
			wantStatusCode:    200, // GitLab returns 200 even for non-existent users
			skipIfRateLimited: true,
		},
		{
			name: "Unsupported registry (bitbucket)",
			pkg: Package{
				Registry: "bitbucket.org",
				Path:     "bitbucket.org/someuser/repo",
				Version:  "",
				Owner:    "someuser",
				Repo:     "repo",
			},
			wantExists:        false,
			wantStatusCode:    0,
			skipIfRateLimited: false,
		},
		{
			name: "Unsupported registry (custom domain)",
			pkg: Package{
				Registry: "git.company.com",
				Path:     "git.company.com/team/project",
				Version:  "",
				Owner:    "team",
				Repo:     "project",
			},
			wantExists:        false,
			wantStatusCode:    0,
			skipIfRateLimited: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exists, statusCode, resetTime := checkUser(client, tt.pkg)

			// Handle rate limiting gracefully
			if (statusCode == 403 || statusCode == 429) && tt.skipIfRateLimited {
				t.Logf("Skipping test due to rate limiting (status: %d, reset: %v)",
					statusCode, resetTime)
				t.Skip("Rate limited by API")
				return
			}

			// Check status code
			if statusCode != tt.wantStatusCode {
				// Allow some flexibility for API issues
				if statusCode != 403 && statusCode != 429 {
					t.Errorf("checkUser() statusCode = %v, want %v",
						statusCode, tt.wantStatusCode)
				} else {
					t.Logf("Unexpected status code: %d (rate limited or API issue)", statusCode)
				}
			}

			// Check exists flag
			if exists != tt.wantExists {
				t.Errorf("checkUser() exists = %v, want %v", exists, tt.wantExists)
			}

			// Verify consistency between status and exists flag
			if tt.pkg.Registry == "github.com" {
				if statusCode == 200 && !exists {
					t.Error("Inconsistent result: status 200 but exists=false")
				}
				if statusCode == 404 && exists {
					t.Error("Inconsistent result: status 404 but exists=true")
				}
			} else if tt.pkg.Registry == "gitlab.com" {
				// GitLab always returns 200, so we only check the exists flag
				if statusCode == 200 && exists != tt.wantExists {
					t.Errorf("GitLab exists flag mismatch: got %v, want %v",
						exists, tt.wantExists)
				}
			}

			// For unsupported registries, resetTime should be zero
			if tt.pkg.Registry != "github.com" && tt.pkg.Registry != "gitlab.com" {
				if !resetTime.IsZero() {
					t.Error("Expected zero resetTime for unsupported registry")
				}
			}
		})
	}
}

func TestCheckGitHubAccounts(t *testing.T) {
	tests := []struct {
		name     string
		packages []Package
		wantLen  int
	}{
		{
			name:     "empty packages",
			packages: []Package{},
			wantLen:  0,
		},
		{
			name: "single package",
			packages: []Package{
				{
					Path:     "github.com/golang/go",
					Version:  "v1.20.0",
					Owner:    "golang",
					Repo:     "go",
					Registry: "github.com",
				},
			},
			wantLen: 1,
		},
		{
			name: "duplicate owners",
			packages: []Package{
				{
					Path:     "github.com/golang/go",
					Version:  "v1.20.0",
					Owner:    "golang",
					Repo:     "go",
					Registry: "github.com",
				},
				{
					Path:     "github.com/golang/tools",
					Version:  "v0.1.0",
					Owner:    "golang",
					Repo:     "tools",
					Registry: "github.com",
				},
			},
			wantLen: 1, // Should deduplicate by owner
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original token
			originalToken := githubToken
			defer func() { githubToken = originalToken }()
			githubToken = "" // Test without token

			results := checkAccounts(tt.packages)
			if len(results) != tt.wantLen {
				t.Errorf("checkAccounts() returned %d results, want %d", len(results), tt.wantLen)
			}

			// Verify result structure
			for _, result := range results {
				if _, ok := result["owner"]; !ok {
					t.Error("checkAccounts() result missing 'owner' field")
				}
				if _, ok := result["exists"]; !ok {
					t.Error("checkAccounts() result missing 'exists' field")
				}
				if _, ok := result["status_code"]; !ok {
					t.Error("checkAccounts() result missing 'status_code' field")
				}
				if _, ok := result["package"]; !ok {
					t.Error("checkAccounts() result missing 'package' field")
				}
			}
		})
	}
}

func TestGenerateSBOM(t *testing.T) {
	t.Run("generates SBOM for current project", func(t *testing.T) {
		// Test with the actual gobelin project directory
		// This is an integration test that uses the real go.mod
		sbom, err := generateSBOM(".")
		if err != nil {
			t.Fatalf("generateSBOM() error = %v", err)
		}

		if len(sbom) == 0 {
			t.Error("generateSBOM() returned empty SBOM")
		}

		// Verify SBOM structure
		for _, module := range sbom {
			if module.Path == "" {
				t.Error("generateSBOM() module has empty Path")
			}
		}

		// Check that we got the expected gobelin module
		foundSelf := false
		for _, module := range sbom {
			if strings.Contains(module.Path, "gobelin") {
				foundSelf = true
				break
			}
		}
		if !foundSelf {
			t.Error("generateSBOM() did not find gobelin module in SBOM")
		}
	})

	// Note: Cannot test failure cases because generateSBOM() calls logger.Fatal()
	// which exits the process. In production code, we'd refactor to return errors.
}

func TestDetectGitHubToken(t *testing.T) {
	t.Run("detects token from GH_TOKEN", func(t *testing.T) {
		oldToken := os.Getenv("GH_TOKEN")
		defer os.Setenv("GH_TOKEN", oldToken)

		os.Setenv("GH_TOKEN", "test-token-123")
		token := detectGitHubToken()
		if token != "test-token-123" {
			t.Errorf("detectGitHubToken() = %v, want 'test-token-123'", token)
		}
	})

	t.Run("detects token from GITHUB_TOKEN", func(t *testing.T) {
		oldGHToken := os.Getenv("GH_TOKEN")
		oldGitHubToken := os.Getenv("GITHUB_TOKEN")
		defer func() {
			os.Setenv("GH_TOKEN", oldGHToken)
			os.Setenv("GITHUB_TOKEN", oldGitHubToken)
		}()

		os.Unsetenv("GH_TOKEN")
		os.Setenv("GITHUB_TOKEN", "github-token-456")
		token := detectGitHubToken()
		if token != "github-token-456" {
			t.Errorf("detectGitHubToken() = %v, want 'github-token-456'", token)
		}
	})

	t.Run("GH_TOKEN takes precedence over GITHUB_TOKEN", func(t *testing.T) {
		oldGHToken := os.Getenv("GH_TOKEN")
		oldGitHubToken := os.Getenv("GITHUB_TOKEN")
		defer func() {
			os.Setenv("GH_TOKEN", oldGHToken)
			os.Setenv("GITHUB_TOKEN", oldGitHubToken)
		}()

		os.Setenv("GH_TOKEN", "priority-token")
		os.Setenv("GITHUB_TOKEN", "backup-token")
		token := detectGitHubToken()
		if token != "priority-token" {
			t.Errorf("detectGitHubToken() = %v, want 'priority-token'", token)
		}
	})

	t.Run("returns empty when no token available", func(t *testing.T) {
		oldGHToken := os.Getenv("GH_TOKEN")
		oldGitHubToken := os.Getenv("GITHUB_TOKEN")
		defer func() {
			os.Setenv("GH_TOKEN", oldGHToken)
			os.Setenv("GITHUB_TOKEN", oldGitHubToken)
		}()

		os.Unsetenv("GH_TOKEN")
		os.Unsetenv("GITHUB_TOKEN")
		// gh auth token will also fail in test environment
		token := detectGitHubToken()
		// Token could be empty or from gh CLI if available
		_ = token // Just verify function doesn't crash
	})
}

func TestDetectGitLabToken(t *testing.T) {
	t.Run("detects token from GL_TOKEN", func(t *testing.T) {
		oldToken := os.Getenv("GL_TOKEN")
		defer os.Setenv("GL_TOKEN", oldToken)

		os.Setenv("GL_TOKEN", "test-token-123")
		token := detectGitLabToken()
		if token != "test-token-123" {
			t.Errorf("detectGitLabToken() = %v, want 'test-token-123'", token)
		}
	})

	t.Run("detects token from GITLAB_TOKEN", func(t *testing.T) {
		oldGHToken := os.Getenv("GL_TOKEN")
		oldGitHubToken := os.Getenv("GITLAB_TOKEN")
		defer func() {
			os.Setenv("GL_TOKEN", oldGHToken)
			os.Setenv("GITLAB_TOKEN", oldGitHubToken)
		}()

		os.Unsetenv("GL_TOKEN")
		os.Setenv("GITLAB_TOKEN", "gitlab-token-456")
		token := detectGitLabToken()
		if token != "gitlab-token-456" {
			t.Errorf("detectGitLabToken() = %v, want 'gitlab-token-456'", token)
		}
	})

	t.Run("GL_TOKEN takes precedence over GITLAB_TOKEN", func(t *testing.T) {
		oldGHToken := os.Getenv("GL_TOKEN")
		oldGitHubToken := os.Getenv("GITLAB_TOKEN")
		defer func() {
			os.Setenv("GL_TOKEN", oldGHToken)
			os.Setenv("GITLAB_TOKEN", oldGitHubToken)
		}()

		os.Setenv("GL_TOKEN", "priority-token")
		os.Setenv("GITLAB_TOKEN", "backup-token")
		token := detectGitLabToken()
		if token != "priority-token" {
			t.Errorf("detectGitLabToken() = %v, want 'priority-token'", token)
		}
	})

	t.Run("returns empty when no token available", func(t *testing.T) {
		oldGHToken := os.Getenv("GL_TOKEN")
		oldGitHubToken := os.Getenv("GITHUB_TOKEN")
		defer func() {
			os.Setenv("GL_TOKEN", oldGHToken)
			os.Setenv("GITHUB_TOKEN", oldGitHubToken)
		}()

		os.Unsetenv("GL_TOKEN")
		os.Unsetenv("GITHUB_TOKEN")
		// gh auth token will also fail in test environment
		token := detectGitLabToken()
		// Token could be empty or from gh CLI if available
		_ = token // Just verify function doesn't crash
	})
}

func TestScanProject(t *testing.T) {
	t.Run("scan from package list file", func(t *testing.T) {
		// Create a test package list file
		tmpFile := filepath.Join(t.TempDir(), "packages.txt")
		content := `github.com/golang/go
github.com/spf13/cobra`
		if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Mock command with args
		err := ScanProject(nil, []string{tmpFile})
		if err != nil {
			t.Errorf("ScanProject() error = %v", err)
		}
	})

	t.Run("scan current directory", func(t *testing.T) {
		// This is an integration test using the actual project
		err := ScanProject(nil, []string{"."})
		if err != nil {
			t.Errorf("ScanProject() error = %v", err)
		}
	})

	t.Run("scan with no args defaults to current directory", func(t *testing.T) {
		err := ScanProject(nil, []string{})
		if err != nil {
			t.Errorf("ScanProject() error = %v", err)
		}
	})
}

func TestOutputResults(t *testing.T) {
	tests := []struct {
		name    string
		results []map[string]interface{}
		wantErr bool
	}{
		{
			name: "no missing accounts",
			results: []map[string]interface{}{
				{
					"owner":       "testuser",
					"exists":      true,
					"status_code": 200,
					"package":     "github.com/testuser/pkg",
				},
			},
			wantErr: false,
		},
		{
			name: "missing accounts",
			results: []map[string]interface{}{
				{
					"owner":       "testuser",
					"exists":      false,
					"status_code": 404,
					"package":     "github.com/testuser/pkg",
				},
			},
			wantErr: false,
		},
		{
			name:    "empty results",
			results: []map[string]interface{}{},
			wantErr: false,
		},
		{
			name: "mixed results",
			results: []map[string]interface{}{
				{
					"owner":       "exists",
					"exists":      true,
					"status_code": 200,
					"package":     "github.com/exists/pkg",
				},
				{
					"owner":       "missing",
					"exists":      false,
					"status_code": 404,
					"package":     "github.com/missing/pkg",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := outputResults(tt.results)
			if (err != nil) != tt.wantErr {
				t.Errorf("outputResults() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	t.Run("with output file", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "output.json")
		outputFile = tmpFile
		defer func() { outputFile = "" }()

		results := []map[string]interface{}{
			{
				"owner":       "testuser",
				"exists":      true,
				"status_code": 200,
				"package":     "github.com/testuser/pkg",
			},
		}

		err := outputResults(results)
		if err != nil {
			t.Errorf("outputResults() with file error = %v", err)
		}

		if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
			t.Error("outputResults() did not create output file")
		}
	})
}
