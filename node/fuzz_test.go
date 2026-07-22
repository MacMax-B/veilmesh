package node

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MacMax-B/propagare/protocol"
)

func FuzzRequestJSONDecoder(f *testing.F) {
	f.Add([]byte(`{"route_tags":[]}`))
	f.Add([]byte(`{"route_tags":[],"unknown":true}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		request := httptest.NewRequest(http.MethodPost, "/v1/fetch", bytes.NewReader(data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var destination protocol.FetchRequest
		_ = decodeJSON(response, request, &destination, 64*1024)
	})
}
