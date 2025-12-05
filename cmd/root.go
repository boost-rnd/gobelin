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
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gobelin",
	Short: "Detect dependencies vulnerable to repojacking",
	Long:  `gobelin scans your Go project dependencies to identify potential repojacking vulnerabilities by verifying that GitHub account owners still exist.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var (
	verbose      bool
	outputFormat string
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&githubToken, "token", "t", "", "GitHub API token (auto-detected from GH_TOKEN, GITHUB_TOKEN, or 'gh auth token')")
	rootCmd.PersistentFlags().StringVarP(&gitlabToken, "gitlab-token", "", "", "Gitlab API token (optional, increases rate limit)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file for results (default: stdout)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text or json")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")
}
