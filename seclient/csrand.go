package seclient

// This file is intentionally minimal. The secureRandomSource adapter and the
// RandomSource variable were previously needed to bridge crypto/rand into the
// math/rand.Source interface (so rand.New could wrap it). Now that randutils.go
// calls crypto/rand.Read directly, the bridge is no longer needed.
//
// The file is kept as a placeholder so any external code that may reference
// the seclient package does not get a compilation failure from a missing file.
// It can be removed entirely once confirmed no external callers remain.
