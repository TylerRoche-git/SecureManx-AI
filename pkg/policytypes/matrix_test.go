package policytypes

import (
	"testing"
)

func TestClassifyConfidence_Low(t *testing.T) {
	got := ClassifyConfidence(0.1)
	if got != BandLow {
		t.Fatalf("expected BandLow for 0.1, got %d", got)
	}
}

func TestClassifyConfidence_Medium(t *testing.T) {
	got := ClassifyConfidence(0.5)
	if got != BandMedium {
		t.Fatalf("expected BandMedium for 0.5, got %d", got)
	}
}

func TestClassifyConfidence_High(t *testing.T) {
	got := ClassifyConfidence(0.8)
	if got != BandHigh {
		t.Fatalf("expected BandHigh for 0.8, got %d", got)
	}
}

func TestClassifyConfidence_Critical(t *testing.T) {
	got := ClassifyConfidence(0.95)
	if got != BandCritical {
		t.Fatalf("expected BandCritical for 0.95, got %d", got)
	}
}

func TestClassifyConfidence_BoundaryAt03(t *testing.T) {
	// 0.3 is >= 0.3 so BandMedium
	got := ClassifyConfidence(0.3)
	if got != BandMedium {
		t.Fatalf("expected BandMedium for boundary 0.3, got %d", got)
	}
}

func TestClassifyConfidence_BoundaryAt07(t *testing.T) {
	// 0.7 is not > 0.7 but >= 0.3 so BandMedium
	got := ClassifyConfidence(0.7)
	if got != BandMedium {
		t.Fatalf("expected BandMedium for boundary 0.7, got %d", got)
	}
}

func TestClassifyConfidence_BoundaryAt09(t *testing.T) {
	// 0.9 is not > 0.9 but > 0.7 so BandHigh
	got := ClassifyConfidence(0.9)
	if got != BandHigh {
		t.Fatalf("expected BandHigh for boundary 0.9, got %d", got)
	}
}

func TestLookupActions_InferenceLow(t *testing.T) {
	matrix := DefaultPolicyMatrix()
	actions := LookupActions(matrix, AssetInference, 0.1)
	assertActionsEqual(t, actions, []ActionType{ActionDetectOnly})
}

func TestLookupActions_InferenceMedium(t *testing.T) {
	matrix := DefaultPolicyMatrix()
	actions := LookupActions(matrix, AssetInference, 0.5)
	assertActionsEqual(t, actions, []ActionType{ActionIsolate})
}

func TestLookupActions_InferenceHigh(t *testing.T) {
	matrix := DefaultPolicyMatrix()
	actions := LookupActions(matrix, AssetInference, 0.8)
	assertActionsEqual(t, actions, []ActionType{ActionKillReplace, ActionBlockEgress})
}

func TestLookupActions_InferenceCritical(t *testing.T) {
	matrix := DefaultPolicyMatrix()
	actions := LookupActions(matrix, AssetInference, 0.95)
	assertActionsEqual(t, actions, []ActionType{ActionQuarantine, ActionRevokeCredentials, ActionFreezePipeline})
}

func TestLookupActions_UnknownAssetReturnsDetectOnly(t *testing.T) {
	matrix := DefaultPolicyMatrix()
	actions := LookupActions(matrix, AssetType("unknown_asset"), 0.8)
	assertActionsEqual(t, actions, []ActionType{ActionDetectOnly})
}

func TestDefaultPolicyMatrix_NonEmptyWithExpectedEntries(t *testing.T) {
	matrix := DefaultPolicyMatrix()
	if len(matrix) == 0 {
		t.Fatal("expected non-empty policy matrix")
	}
	// 6 asset types * 4 bands = 24 entries
	expectedCount := 24
	if len(matrix) != expectedCount {
		t.Fatalf("expected %d matrix entries, got %d", expectedCount, len(matrix))
	}
}

// assertActionsEqual verifies that two action slices contain the same elements in order.
func assertActionsEqual(t *testing.T, got, want []ActionType) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("action count mismatch: got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("action[%d] mismatch: got %q, want %q", i, got[i], want[i])
		}
	}
}
