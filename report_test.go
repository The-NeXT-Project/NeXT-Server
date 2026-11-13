package nextserver

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/api/serverv1"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

type sentReport struct {
	id      string
	traffic map[int][2]int64
}

// trafficOutbox wires an outbox to a real user table and a fake panel that
// answers with the errors in answers, one per request, then nil.
func trafficOutbox(table *userTable, answers ...error) (*reportOutbox[adapter.UserTraffic], *[]sentReport) {
	var sent []sentReport
	outbox := &reportOutbox[adapter.UserTraffic]{
		name:    "traffic",
		logger:  log.NewNOPFactory().Logger(),
		collect: table.collectTraffic,
		restore: table.restoreTraffic,
		send: func(_ context.Context, reportID string, items []adapter.UserTraffic) error {
			sent = append(sent, sentReport{reportID, trafficOf(items)})
			if len(answers) == 0 {
				return nil
			}
			answer := answers[0]
			answers = answers[1:]
			return answer
		},
	}
	return outbox, &sent
}

var timeout = E.Cause(context.DeadlineExceeded, "POST /users/traffic")

func TestReportOutboxResendsAFailedBatchUnchanged(t *testing.T) {
	table := newUserTable(context.Background())
	table.update([]adapter.User{{ID: 1}, {ID: 2}}, 0)
	outbox, sent := trafficOutbox(table, timeout, &serverv1.Error{Status: 504})
	ctx := context.Background()

	table.get(1).upload.Add(5)
	if outbox.flush(ctx) == nil {
		t.Fatal("a timeout was not reported")
	}
	if !outbox.pending() {
		t.Fatal("the failed batch was not kept")
	}
	// Traffic that arrives meanwhile waits at its source, and the batch
	// goes again as it was.
	table.get(1).upload.Add(7)
	table.get(2).download.Add(3)
	if outbox.flush(ctx) == nil {
		t.Fatal("a gateway timeout was not reported")
	}
	if err := outbox.flush(ctx); err != nil {
		t.Fatal(err)
	}
	if outbox.pending() {
		t.Fatal("a delivered batch is still pending")
	}

	if len(*sent) != 4 {
		t.Fatalf("sent %d reports, want 3 attempts of the first batch and the new one: %v", len(*sent), *sent)
	}
	first := (*sent)[0]
	for _, attempt := range (*sent)[1:3] {
		if attempt.id != first.id || len(attempt.traffic) != 1 || attempt.traffic[1] != [2]int64{5, 0} {
			t.Fatalf("the resend changed: %+v, first %+v", attempt, first)
		}
	}
	// Once the pending batch is through, the new traffic goes in a new batch.
	next := (*sent)[3]
	if next.id == first.id || next.traffic[1] != [2]int64{7, 0} || next.traffic[2] != [2]int64{0, 3} {
		t.Fatalf("new batch: %+v", next)
	}
	if err := outbox.flush(ctx); err != nil || len(*sent) != 4 {
		t.Fatal("an idle flush sent something: ", *sent)
	}
}

// A 4xx means the panel recorded nothing, so the counts go back and travel
// in a fresh batch, instead of a refused batch blocking all later ones.
func TestReportOutboxReturnsARefusedBatch(t *testing.T) {
	for _, status := range []int{400, 401, 403, 429} {
		table := newUserTable(context.Background())
		table.update([]adapter.User{{ID: 1}}, 0)
		refusal := E.Cause(&serverv1.Error{Status: status, Code: "invalid_body"}, "POST /users/traffic")
		outbox, sent := trafficOutbox(table, refusal)
		ctx := context.Background()

		table.get(1).upload.Add(5)
		if err := outbox.flush(ctx); !adapter.IsRefused(err) {
			t.Fatalf("%d: refusal lost: %v", status, err)
		}
		if outbox.pending() {
			t.Fatalf("%d: a refused batch is kept for resending", status)
		}
		table.get(1).upload.Add(2)
		if err := outbox.flush(ctx); err != nil {
			t.Fatal(err)
		}
		if len(*sent) != 2 || (*sent)[1].id == (*sent)[0].id || (*sent)[1].traffic[1] != [2]int64{7, 0} {
			t.Fatalf("%d: after a refusal: %+v", status, *sent)
		}
	}
}

// A refused batch for a user dropped meanwhile is not lost either.
func TestReportOutboxReturnsTrafficOfARemovedUser(t *testing.T) {
	table := newUserTable(context.Background())
	table.update([]adapter.User{{ID: 1}}, 0)
	outbox, sent := trafficOutbox(table, &serverv1.Error{Status: 403})
	table.get(1).download.Add(9)
	table.update(nil, 0)
	outbox.flush(context.Background())
	if err := outbox.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2 || (*sent)[1].traffic[1] != [2]int64{0, 9} {
		t.Fatal("traffic of a removed user lost after a refusal: ", *sent)
	}
}

func TestReportOutboxDetectLogs(t *testing.T) {
	auditor := newAuditor()
	var sent [][]adapter.DetectLog
	var ids []string
	answers := []error{errors.New("connection reset"), nil}
	outbox := &reportOutbox[adapter.DetectLog]{
		name:    "detect log",
		logger:  log.NewNOPFactory().Logger(),
		collect: auditor.collect,
		restore: auditor.restore,
		send: func(_ context.Context, reportID string, items []adapter.DetectLog) error {
			sent = append(sent, items)
			ids = append(ids, reportID)
			answer := answers[0]
			answers = answers[1:]
			return answer
		},
	}
	auditor.record(1, 1)
	outbox.flush(context.Background())
	// A hit recorded again while the batch is pending is not merged into it.
	auditor.record(1, 1)
	auditor.record(2, 1)
	answers = append(answers, nil)
	if err := outbox.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 3 || ids[0] != ids[1] || len(sent[1]) != 1 || ids[2] == ids[0] || len(sent[2]) != 2 {
		t.Fatalf("sent %v under %v", sent, ids)
	}
}

func TestReportIDs(t *testing.T) {
	format := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := make(map[string]bool)
	for range 1000 {
		id := newReportID()
		if !format.MatchString(id) || seen[id] {
			t.Fatal("bad or repeated report ID: ", id)
		}
		seen[id] = true
	}
}
