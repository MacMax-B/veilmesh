//go:build windows

package privatefs

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Kind uint8

const (
	RegularFile Kind = iota + 1
	Directory
)

type privatePrincipals struct {
	user           *windows.SID
	system         *windows.SID
	administrators *windows.SID
}

const windowsFileAllAccess windows.ACCESS_MASK = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff

var (
	principalsOnce sync.Once
	principals     privatePrincipals
	principalsErr  error
)

func loadPrivatePrincipals() (privatePrincipals, error) {
	principalsOnce.Do(func() {
		tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || tokenUser == nil || tokenUser.User.Sid == nil {
			principalsErr = errors.New("current Windows user SID is unavailable")
			return
		}
		principals.user, err = tokenUser.User.Sid.Copy()
		if err != nil {
			principalsErr = err
			return
		}
		principals.system, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid)
		if err != nil {
			principalsErr = err
			return
		}
		principals.administrators, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			principalsErr = err
		}
	})
	return principals, principalsErr
}

// Restrict installs a protected DACL granting full access only to the current
// service user, LocalSystem, and the local Administrators group. Directories
// propagate the same allow-list to newly created descendants.
func Restrict(path string, kind Kind) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := validateObjectType(info, kind); err != nil {
		return err
	}
	trusted, err := loadPrivatePrincipals()
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if kind == Directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	unique := trusted.unique()
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(unique))
	for index, sid := range unique {
		trusteeType := windows.TRUSTEE_TYPE(windows.TRUSTEE_IS_GROUP)
		if index == 0 {
			trusteeType = windows.TRUSTEE_TYPE(windows.TRUSTEE_IS_USER)
		}
		entries = append(entries, privateAccessEntry(sid, trusteeType, inheritance))
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		return errors.New("private Windows filesystem path changed while applying its DACL")
	}
	return Validate(path, current, kind)
}

func privateAccessEntry(sid *windows.SID, trusteeType windows.TRUSTEE_TYPE, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

// Validate checks the protected DACL instead of POSIX mode bits, which do not
// represent Windows ACLs. No untrusted allow ACE is accepted.
func Validate(path string, info os.FileInfo, kind Kind) error {
	if err := validateObjectType(info, kind); err != nil {
		return err
	}
	trusted, err := loadPrivatePrincipals()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("private Windows security descriptor is unavailable")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("private Windows DACL inherits external permissions")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !trustedSID(owner, trusted) {
		return errors.New("private Windows object has an untrusted owner")
	}
	unique := trusted.unique()
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("private Windows object has an unexpected DACL")
	}
	if int(dacl.AceCount) != len(unique) {
		return fmt.Errorf("private Windows object has %d DACL entries, want %d: %s", dacl.AceCount, len(unique), describeWindowsACL(dacl))
	}
	seen := make([]bool, len(unique))
	expectedFlags := uint8(windows.NO_INHERITANCE)
	if kind == Directory {
		expectedFlags = uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != expectedFlags ||
			!fullWindowsFileAccess(ace.Mask) {
			return errors.New("private Windows DACL contains an unsupported ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return errors.New("private Windows DACL contains an invalid SID")
		}
		matched := false
		for principalIndex, allowed := range unique {
			if sid.Equals(allowed) && !seen[principalIndex] {
				seen[principalIndex] = true
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("private Windows DACL grants an untrusted or duplicate principal")
		}
	}
	for _, present := range seen {
		if !present {
			return errors.New("private Windows DACL is missing a trusted principal")
		}
	}
	return nil
}

func describeWindowsACL(dacl *windows.ACL) string {
	if dacl == nil {
		return "unavailable"
	}
	entries := make([]string, 0, dacl.AceCount)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			entries = append(entries, fmt.Sprintf("%d:unreadable", index))
			continue
		}
		entries = append(entries, fmt.Sprintf("%d:type=%#x flags=%#x mask=%#x", index, ace.Header.AceType, ace.Header.AceFlags, ace.Mask))
	}
	return strings.Join(entries, ", ")
}

// ValidateKeyParent currently requires the same protected Windows DACL as a
// private directory. Windows generic masks and inherited object-specific ACEs
// are not interpreted permissively at this key-management boundary.
func ValidateKeyParent(path string, info os.FileInfo) error {
	return Validate(path, info, Directory)
}

// Replace uses the documented Windows write-through rename so a successful
// critical record publication does not depend on an unsupported directory
// FlushFileBuffers operation.
func Replace(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// PublishNoReplace omits MOVEFILE_REPLACE_EXISTING and therefore fails if the
// destination already exists. Success consumes source.
func PublishNoReplace(source, target string) (bool, error) {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return false, err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return false, err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return false, err
	}
	return true, nil
}

func validateObjectType(info os.FileInfo, kind Kind) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private Windows filesystem object is missing or a symlink")
	}
	switch kind {
	case RegularFile:
		if !info.Mode().IsRegular() {
			return errors.New("private Windows filesystem object is not a regular file")
		}
	case Directory:
		if !info.IsDir() {
			return errors.New("private Windows filesystem object is not a directory")
		}
	default:
		return errors.New("invalid private filesystem object kind")
	}
	return nil
}

func trustedSID(candidate *windows.SID, trusted privatePrincipals) bool {
	if candidate == nil || !candidate.IsValid() {
		return false
	}
	for _, sid := range trusted.unique() {
		if candidate.Equals(sid) {
			return true
		}
	}
	return false
}

func (trusted privatePrincipals) unique() []*windows.SID {
	result := make([]*windows.SID, 0, 3)
	for _, candidate := range []*windows.SID{trusted.user, trusted.system, trusted.administrators} {
		duplicate := false
		for _, existing := range result {
			if candidate != nil && existing.Equals(candidate) {
				duplicate = true
				break
			}
		}
		if candidate != nil && !duplicate {
			result = append(result, candidate)
		}
	}
	return result
}

func fullWindowsFileAccess(mask windows.ACCESS_MASK) bool {
	return mask&windows.GENERIC_ALL == windows.GENERIC_ALL || mask&windowsFileAllAccess == windowsFileAllAccess
}
