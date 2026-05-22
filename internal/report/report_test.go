package report

import "testing"

func TestSummaryCountsEventsByDecisionAndKind(t *testing.T) {
	r := New()
	r.Record(Event{Kind: EventWrite, Decision: DecisionWouldBlock, Target: "/etc/passwd"})
	r.Record(Event{Kind: EventConnect, Decision: DecisionWouldBlock, Target: "10.1.2.3:443"})
	r.Record(Event{Kind: EventConnect, Decision: DecisionAllowed, Target: "1.1.1.1:443"})

	summary := r.Summary()

	if summary.Total != 3 {
		t.Fatalf("total = %d, want 3", summary.Total)
	}
	if summary.WouldBlock != 2 {
		t.Fatalf("would block = %d, want 2", summary.WouldBlock)
	}
	if summary.ByKind[EventConnect] != 2 {
		t.Fatalf("connect count = %d, want 2", summary.ByKind[EventConnect])
	}
	if summary.ByKind[EventWrite] != 1 {
		t.Fatalf("write count = %d, want 1", summary.ByKind[EventWrite])
	}
}

func TestEventsReturnsCopy(t *testing.T) {
	r := New()
	r.Record(Event{Kind: EventWrite, Decision: DecisionWouldBlock, Target: "/etc/passwd"})

	events := r.Events()
	events[0].Target = "/tmp/changed"

	if got := r.Events()[0].Target; got != "/etc/passwd" {
		t.Fatalf("stored target = %q, want original target", got)
	}
}
