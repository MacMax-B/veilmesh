//go:build windows

package privatefs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateDACLAcceptsCanonicalDirectoryAndFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Restrict(directory, Directory); err != nil {
		t.Fatalf("restrict directory: %v", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(directory, info, Directory); err != nil {
		t.Fatalf("validate directory: %v", err)
	}

	file := filepath.Join(directory, "secret")
	if err := os.WriteFile(file, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restrict(file, RegularFile); err != nil {
		t.Fatalf("restrict file: %v", err)
	}
	info, err = os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(file, info, RegularFile); err != nil {
		t.Fatalf("validate file: %v", err)
	}
}

func TestWindowsPrivateDACLRejectsUntrustedAllowACE(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(file, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restrict(file, RegularFile); err != nil {
		t.Fatalf("restrict file: %v", err)
	}

	descriptor, err := windows.GetNamedSecurityInfo(
		file,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read DACL: %v", err)
	}
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	untrusted := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(world),
		},
	}
	tampered, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{untrusted}, dacl)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		file,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		tampered,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(file, info, RegularFile); err == nil {
		t.Fatal("Validate accepted an untrusted allow ACE")
	}
}

func TestWindowsACEPermissionsRejectsUnsafeInheritance(t *testing.T) {
	tests := []struct {
		name  string
		flags uint8
		kind  Kind
	}{
		{name: "file-inherits", flags: uint8(windows.OBJECT_INHERIT_ACE), kind: RegularFile},
		{name: "directory-object-only", flags: uint8(windows.OBJECT_INHERIT_ACE), kind: Directory},
		{name: "directory-container-only", flags: uint8(windows.CONTAINER_INHERIT_ACE), kind: Directory},
		{name: "directory-inherited", flags: uint8(windows.INHERITED_ACE), kind: Directory},
		{name: "directory-no-propagate", flags: uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE | windows.NO_PROPAGATE_INHERIT_ACE), kind: Directory},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, valid := windowsACEPermissions(test.flags, test.kind); valid {
				t.Fatalf("accepted unsafe inheritance flags %#x", test.flags)
			}
		})
	}
}
