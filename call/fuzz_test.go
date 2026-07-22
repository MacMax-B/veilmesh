package call

import "testing"

func FuzzCallID(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB")
	f.Fuzz(func(t *testing.T, callID string) {
		_ = validCallID(callID)
	})
}

func FuzzValidateSDP(f *testing.F) {
	f.Add(testAudioSDP, true, false)
	f.Add("", true, false)
	f.Fuzz(func(t *testing.T, raw string, audio, video bool) {
		_ = validateSDP(raw, Media{Audio: audio, Video: video})
	})
}
