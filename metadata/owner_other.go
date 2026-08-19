//go:build !darwin && !linux

package metadata

import "os"

// Serve rejects Unix sockets on Windows before this check. Return false on an
// unqualified platform instead of silently weakening the directory boundary.
func ownedByEffectiveUser(os.FileInfo) bool { return false }
