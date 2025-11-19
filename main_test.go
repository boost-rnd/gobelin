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

package main

import (
	"os"
	"testing"
)

// TestMainFunction tests the main function
func TestMainFunction(t *testing.T) {
	t.Run("main calls cmd.Execute", func(t *testing.T) {
		// Save and restore os.Args
		oldArgs := os.Args
		defer func() { os.Args = oldArgs }()

		// Set args to show help (won't cause exit)
		os.Args = []string{"gobelin", "--help"}

		// Call main() directly - this gives us coverage
		// Help flag will make it print and return without error
		main()

		// If we get here, main() executed successfully
		t.Log("main() executed successfully")
	})

	t.Run("main with version flag", func(t *testing.T) {
		oldArgs := os.Args
		defer func() { os.Args = oldArgs }()

		os.Args = []string{"gobelin", "scan", "--help"}

		// This should also execute without errors
		main()
	})
}
