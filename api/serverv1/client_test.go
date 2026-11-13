package serverv1

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/option"
)

func TestReportsCarryTheReportID(t *testing.T) {
	bodies := make(map[string]map[string]any)
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(content, &body); err != nil {
			t.Error(err)
		}
		bodies[r.URL.Path] = body
		w.WriteHeader(status)
		w.Write([]byte(`{"data": {"accepted": 0, "skipped": 0, "duplicate": true}}`))
	}))
	defer server.Close()
	client, err := NewClient(option.ServerOptions{URL: server.URL, Key: "key"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// A duplicate answer is a success: the batch is delivered.
	if err = client.ReportTraffic(ctx, "abc", []adapter.UserTraffic{{UserID: 1, Upload: 2, Download: 3}}); err != nil {
		t.Fatal(err)
	}
	if err = client.ReportDetectLogs(ctx, "def", []adapter.DetectLog{{UserID: 1, RuleID: 4}}); err != nil {
		t.Fatal(err)
	}
	if id := bodies["/api/server/v1/users/traffic"]["report_id"]; id != "abc" {
		t.Error("traffic report_id: ", id)
	}
	if id := bodies["/api/server/v1/users/detect_logs"]["report_id"]; id != "def" {
		t.Error("detect log report_id: ", id)
	}
	// The panel refuses an empty ID, so none is sent.
	client.ReportTraffic(ctx, "", []adapter.UserTraffic{{UserID: 1, Upload: 2}})
	if _, sent := bodies["/api/server/v1/users/traffic"]["report_id"]; sent {
		t.Error("empty report_id sent")
	}

	for _, testCase := range []struct {
		status  int
		refused bool
	}{
		{http.StatusBadRequest, true},
		{http.StatusUnauthorized, true},
		{http.StatusForbidden, true},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, false},
		{http.StatusBadGateway, false},
		{http.StatusGatewayTimeout, false},
	} {
		status = testCase.status
		err = client.ReportTraffic(ctx, "abc", []adapter.UserTraffic{{UserID: 1, Upload: 2}})
		if err == nil || adapter.IsRefused(err) != testCase.refused {
			t.Errorf("HTTP %d: refused = %v (%v)", testCase.status, adapter.IsRefused(err), err)
		}
	}

	// Without an answer the outcome is open.
	server.Close()
	if err = client.ReportTraffic(ctx, "abc", nil); err == nil || adapter.IsRefused(err) {
		t.Error("a failed connection counts as a refusal: ", err)
	}
}
