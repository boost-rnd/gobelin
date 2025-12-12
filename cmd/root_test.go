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
	"testing"
)

func TestRootCmd(t *testing.T) {
	t.Run("root command has correct properties", func(t *testing.T) {
		if rootCmd.Use != "gobelin" {
			t.Errorf("rootCmd.Use = %v, want 'gobelin'", rootCmd.Use)
		}
		if rootCmd.Short == "" {
			t.Error("rootCmd.Short should not be empty")
		}
		if rootCmd.Long == "" {
			t.Error("rootCmd.Long should not be empty")
		}
	})

	t.Run("root command has persistent flags", func(t *testing.T) {
		tokenFlag := rootCmd.PersistentFlags().Lookup("token")
		if tokenFlag == nil {
			t.Error("rootCmd should have --token flag")
		}

		gitlabTokenFlag := rootCmd.PersistentFlags().Lookup("gitlab-token")
		if gitlabTokenFlag == nil {
			t.Error("rootCmd should have --gitlab-token flag")
		}

		outputFlag := rootCmd.PersistentFlags().Lookup("output")
		if outputFlag == nil {
			t.Error("rootCmd should have --output flag")
		}
	})

	t.Run("scan command is registered", func(t *testing.T) {
		found := false
		for _, cmd := range rootCmd.Commands() {
			if cmd.Name() == "scan" {
				found = true
				break
			}
		}
		if !found {
			t.Error("scan command should be registered with root command")
		}
	})
}

func TestExecute(t *testing.T) {
	t.Run("Execute runs successfully with help flag", func(t *testing.T) {
		// Set up args to show help (which will succeed without errors)
		oldArgs := os.Args
		defer func() { os.Args = oldArgs }()

		os.Args = []string{"gobelin", "--help"}

		// Execute should run the help command successfully
		// This will call rootCmd.Execute() which covers the Execute function
		// Note: This will print help to stdout but won't exit
		Execute()

		// If we get here, Execute() was called successfully
	})
}
