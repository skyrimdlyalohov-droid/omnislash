package probe

import (
	"bytes"
	"errors"
	"testing"

	"github.com/skyrimdlyalohov-droid/omnislash/obfuscation"
	"github.com/skyrimdlyalohov-droid/omnislash/util"
)

var rareFramingModes = []MutationMode{
	MutationOWSBeforeColon,
	MutationOWSInValue,
	MutationConflictingFraming,
	MutationChunkBoundaryExt,
}

func TestRareFramingModesAreOptInAndScopeGated(t *testing.T) {
	base := []byte(mutatorBaseRequest)
	for _, mode := range rareFramingModes {
		t.Run(string(mode), func(t *testing.T) {
			var denied *PayloadMutator = &PayloadMutator{
				Target: "lab.test:80",
				Mode:   mode,
			}
			if _, err := denied.Mutate(base, 5); !errors.Is(err, ErrMutationScopeDenied) {
				t.Fatalf("error = %v, want ErrMutationScopeDenied", err)
			}

			denied.Scope = denyScope{}
			if _, err := denied.Mutate(base, 5); !errors.Is(err, ErrMutationScopeDenied) {
				t.Fatalf("deny guard error = %v, want ErrMutationScopeDenied", err)
			}

			out, err := safeMutate(testMutator(mode, nil), base, 5)
			if err != nil {
				t.Fatal(err)
			}
			opts := obfuscation.FramingOptionsFromSeed(5)
			want, err := obfuscation.ApplyFramingMutation(base, obfuscation.FramingMode(mode), opts)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, want) {
				t.Fatalf("payload mutator bytes =\n%q\nwant\n%q", out, want)
			}
			if bytes.Count(out, []byte("\r\n")) != bytes.Count(base, []byte("\r\n")) {
				t.Fatal("rare framing mutation changed the CRLF count")
			}
			if !validCRLF(out) {
				t.Fatal("rare framing mutation introduced a bare CR or LF")
			}
		})
	}
}

func TestRareFramingModesSkipRequestsWithoutFraming(t *testing.T) {
	get := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	for _, mode := range rareFramingModes {
		t.Run(string(mode), func(t *testing.T) {
			out, err := safeMutate(testMutator(mode, nil), get, 5)
			if err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if !bytes.Equal(out, get) {
				t.Fatalf("payload = %q, want unchanged GET", out)
			}
		})
	}
}

func TestRareFramingModesDoNotEnterAutoRotation(t *testing.T) {
	seen := make(map[MutationMode]struct{}, len(mutationModeOrder))
	for _, mode := range mutationModeOrder {
		seen[mode] = struct{}{}
	}
	for _, mode := range rareFramingModes {
		if _, ok := seen[mode]; ok {
			t.Fatalf("opt-in mode %q must not be in MutationAuto", mode)
		}
	}
}

func TestRareFramingPanicBecomesEngineFault(t *testing.T) {
	t.Setenv("OMNISLASH_PANIC_AUDIT", t.TempDir()+"/panic_audit.log")
	mut := testMutator(MutationChunkBoundaryExt, panicPool{})
	if _, err := safeMutate(mut, []byte(mutatorBaseRequest), 7); !errors.Is(err, util.ErrPrecisionLost) {
		t.Fatalf("panic error = %v, want ErrPrecisionLost", err)
	}
	state, _ := safeAnalyze(&ParserStateMachine{}, nil, util.ErrPrecisionLost)
	if state != EngineFault {
		t.Fatalf("FSM state = %s, want Engine_Fault", state)
	}
}
