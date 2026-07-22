package releaseinfo

import "testing"

func TestStringFallsBackToStableDevelopmentIdentity(t *testing.T) {
	originalVersion, originalCommit := Version, Commit
	t.Cleanup(func() { Version, Commit = originalVersion, originalCommit })

	Version, Commit = " ", " "
	if got := String(); got != "dev" {
		t.Fatalf("empty metadata produced %q, want dev", got)
	}
	Version, Commit = "0.1.0-preview.1", "abcdef012345"
	if got := String(); got != "0.1.0-preview.1 (abcdef012345)" {
		t.Fatalf("release metadata produced %q", got)
	}
}
