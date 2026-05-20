package collector

import "testing"

func TestTruncate_WithinCap(t *testing.T) {
	items := []int{3, 1, 2}
	kept, dropped, truncated := Truncate(items, 5, func(a, b int) bool { return a < b })

	if truncated {
		t.Error("truncated = true, want false when within cap")
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
	// Within cap, the slice is returned unchanged (no sort applied).
	if len(kept) != 3 || kept[0] != 3 {
		t.Errorf("kept = %v, want unchanged [3 1 2]", kept)
	}
}

func TestTruncate_ExceedsCap(t *testing.T) {
	items := []int{1, 5, 3, 2, 4}
	// less = descending, so the largest survive truncation.
	kept, dropped, truncated := Truncate(items, 2, func(a, b int) bool { return a > b })

	if !truncated {
		t.Error("truncated = false, want true when over cap")
	}
	if dropped != 3 {
		t.Errorf("dropped = %d, want 3", dropped)
	}
	if len(kept) != 2 || kept[0] != 5 || kept[1] != 4 {
		t.Errorf("kept = %v, want [5 4] (highest survive desc sort)", kept)
	}
}

func TestTruncate_StableSort(t *testing.T) {
	type row struct {
		sev   int
		order int
	}
	items := []row{
		{sev: 1, order: 0},
		{sev: 1, order: 1},
		{sev: 1, order: 2},
	}
	// Equal severity: stable sort preserves insertion order.
	kept, _, truncated := Truncate(items, 2, func(a, b row) bool { return a.sev > b.sev })
	if !truncated {
		t.Fatal("expected truncation")
	}
	if kept[0].order != 0 || kept[1].order != 1 {
		t.Errorf("kept order = %d,%d, want 0,1 (stable)", kept[0].order, kept[1].order)
	}
}

func TestTruncate_EmptyAndExactCap(t *testing.T) {
	empty := []int{}
	kept, dropped, truncated := Truncate(empty, 5, func(a, b int) bool { return a < b })
	if truncated || dropped != 0 || len(kept) != 0 {
		t.Errorf("empty slice: got kept=%v dropped=%d truncated=%v", kept, dropped, truncated)
	}

	exact := []int{1, 2, 3}
	kept, dropped, truncated = Truncate(exact, 3, func(a, b int) bool { return a < b })
	if truncated || dropped != 0 || len(kept) != 3 {
		t.Errorf("exact cap: got kept=%v dropped=%d truncated=%v", kept, dropped, truncated)
	}
}
