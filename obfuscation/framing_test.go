package obfuscation

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/skyrimdlyalohov-droid/omnislash/util"
)

const framingBaseRequest = "GET /x HTTP/1.1\r\n" +
	"Host: lab.test\r\n" +
	"Content-Length: 4\r\n" +
	"Transfer-Encoding: chunked\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"4\r\nabcd\r\n0\r\n\r\n"

func TestApplyFramingMutationByteExact(t *testing.T) {
	base := []byte(framingBaseRequest)
	cases := []struct {
		name     string
		mode     FramingMode
		opts     FramingOptions
		wantCL   string
		wantTE   string
		wantBody string
	}{
		{
			name:     "ows before colon",
			mode:     FramingOWSBeforeColon,
			opts:     FramingOptions{OWS: 0x0b},
			wantCL:   "Content-Length\x0b:\x0b 4",
			wantTE:   "Transfer-Encoding\x0b:\x0b chunked",
			wantBody: "4\r\nabcd\r\n0\r\n\r\n",
		},
		{
			name:     "ows inside value",
			mode:     FramingOWSInValue,
			opts:     FramingOptions{OWS: 0x0c},
			wantCL:   "Content-Length: 4\x0c",
			wantTE:   "Transfer-Encoding: c\x0chunked",
			wantBody: "4\r\nabcd\r\n0\r\n\r\n",
		},
		{
			name:     "conflicting framing values",
			mode:     FramingConflictingHeaders,
			opts:     FramingOptions{OWS: 0x09, Variant: 0},
			wantCL:   "Content-Length: 4, 0",
			wantTE:   "Transfer-Encoding: chunked, identity",
			wantBody: "4\r\nabcd\r\n0\r\n\r\n",
		},
		{
			name:     "conflicting cow and chunked with case mixing",
			mode:     FramingConflictingHeaders,
			opts:     FramingOptions{OWS: 0x09, Variant: 2, FlipCase: true},
			wantCL:   "cONTENT-lENGTH: 4, 00",
			wantTE:   "tRANSFER-eNCODING: cow, chunked",
			wantBody: "4\r\nabcd\r\n0\r\n\r\n",
		},
		{
			name:     "chunk extension with boundary bytes",
			mode:     FramingChunkBoundary,
			opts:     FramingOptions{OWS: 0x09},
			wantCL:   "Content-Length: 4",
			wantTE:   "Transfer-Encoding: chunked",
			wantBody: "4;\tx=\t1\r\nabcd\r\n0\r\n\r\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ApplyFramingMutation(base, tc.mode, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			wantHead := []string{
				"GET /x HTTP/1.1", "Host: lab.test", tc.wantCL, tc.wantTE, "Connection: close",
			}
			want := strings.Join(wantHead, "\r\n") + "\r\n\r\n" + tc.wantBody
			if string(out) != want {
				t.Fatalf("mutation bytes =\n%q\nwant\n%q", out, want)
			}
			if bytes.Count(out, lineSeparator) != bytes.Count(base, lineSeparator) {
				t.Fatalf("CRLF count changed: base=%d out=%d", bytes.Count(base, lineSeparator), bytes.Count(out, lineSeparator))
			}
			if bytes.Count(out, requestSeparator) != bytes.Count(base, requestSeparator) {
				t.Fatalf("header terminator count changed")
			}
			if !validFramingCRLF(out) {
				t.Fatalf("mutation introduced a bare CR or LF: %q", out)
			}
		})
	}
}

func TestApplyFramingMutationRewritesRepeatedHeadersInPlace(t *testing.T) {
	base := []byte("POST /x HTTP/1.1\r\nHost: lab.test\r\n" +
		"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n" +
		"Content-Length: 6\r\nContent-Length: 6\r\n\r\n0\r\n\r\n")
	out, err := ApplyFramingMutation(base, FramingConflictingHeaders, FramingOptions{OWS: 0x09, Variant: 0})
	if err != nil {
		t.Fatal(err)
	}
	want := "POST /x HTTP/1.1\r\nHost: lab.test\r\n" +
		"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n" +
		"Content-Length: 4\r\nContent-Length: 0\r\n\r\n0\r\n\r\n"
	if string(out) != want {
		t.Fatalf("repeated header mutation =\n%q\nwant\n%q", out, want)
	}
	if bytes.Count(out, lineSeparator) != bytes.Count(base, lineSeparator) {
		t.Fatal("duplicate framing headers must not add a CRLF boundary")
	}
}

func TestApplyFramingMutationFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		mode FramingMode
		opts FramingOptions
		want error
	}{
		{"bare LF", "GET / HTTP/1.1\nHost: lab.test\r\n\r\n", FramingOWSBeforeColon, FramingOptions{}, util.ErrPrecisionLost},
		{"no terminator", "GET / HTTP/1.1\r\nHost: lab.test\r\n", FramingOWSBeforeColon, FramingOptions{}, util.ErrPrecisionLost},
		{"unknown mode", framingBaseRequest, FramingMode("nope"), FramingOptions{}, ErrFramingMode},
		{"invalid OWS", framingBaseRequest, FramingOWSBeforeColon, FramingOptions{OWS: 0x0d}, ErrOWSByte},
		{"no framing header", "GET / HTTP/1.1\r\nHost: lab.test\r\nAccept: */*\r\n\r\n", FramingOWSBeforeColon, FramingOptions{}, ErrNoFramingHeader},
		{"no conflict source", "GET / HTTP/1.1\r\nHost: lab.test\r\nAccept: */*\r\n\r\n", FramingConflictingHeaders, FramingOptions{}, ErrNoFramingHeader},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ApplyFramingMutation([]byte(tc.raw), tc.mode, tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestApplyFramingMutationSeededIsDeterministic(t *testing.T) {
	base := []byte(framingBaseRequest)
	for _, mode := range []FramingMode{
		FramingOWSBeforeColon, FramingOWSInValue,
		FramingConflictingHeaders, FramingChunkBoundary,
	} {
		first, err := ApplyFramingMutationSeeded(base, mode, 19)
		if err != nil {
			t.Fatal(err)
		}
		second, err := ApplyFramingMutationSeeded(base, mode, 19)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("seed %d produced different bytes for %s: %q vs %q", 19, mode, first, second)
		}
	}
}
