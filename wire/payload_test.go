package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

type payloadTerminalReader struct {
	*bytes.Reader
	err error
}

func (r *payloadTerminalReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if r.Reader.Len() == 0 && r.err != nil {
		err := r.err
		r.err = nil
		return n, err
	}
	return n, err
}

func TestReadPayloadBoundaries(t *testing.T) {
	for _, size := range []uint32{0, 17, 64 * 1024, 64*1024 + 1, 1024 * 1024} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			body := bytes.Repeat([]byte{0x5a}, int(size))
			r := bytes.NewReader(append(body, 0xaa))
			got, err := readPayload(r, size)
			if err != nil || !bytes.Equal(got, body) || r.Len() != 1 {
				t.Fatalf("payload or frame boundary changed: got=%d remaining=%d err=%v", len(got), r.Len(), err)
			}
		})
	}
}

func TestReadPayloadErrors(t *testing.T) {
	broken := errors.New("connection interrupted")
	for _, size := range []uint32{32, 64*1024 + 1} {
		for _, tc := range []struct {
			name string
			n    int
			err  error
			want error
		}{
			{"empty", 0, io.EOF, io.EOF},
			{"partial", 3, io.EOF, io.ErrUnexpectedEOF},
			{"last-byte-missing", int(size) - 1, io.EOF, io.ErrUnexpectedEOF},
			{"interrupted", 3, broken, broken},
			{"chunk-boundary-error", min(int(size)-1, 64*1024), broken, broken},
			{"full-with-error", int(size), broken, nil},
		} {
			t.Run(fmt.Sprintf("%d/%s", size, tc.name), func(t *testing.T) {
				r := &payloadTerminalReader{bytes.NewReader(make([]byte, tc.n)), tc.err}
				got, err := readPayload(r, size)
				if len(got) != tc.n || err != tc.want {
					t.Fatalf("got (%d, %v), want (%d, %v)", len(got), err, tc.n, tc.want)
				}
			})
		}
	}
}

var payloadBenchmarkSink []byte

func BenchmarkReadPayload(b *testing.B) {
	readers := []struct {
		name string
		read func(io.Reader, uint32) ([]byte, error)
	}{
		{"previous", func(r io.Reader, size uint32) ([]byte, error) {
			p := make([]byte, size)
			n, err := io.ReadFull(r, p)
			return p[:n], err
		}},
		{"progressive", readPayload},
	}
	for _, tc := range []struct {
		name     string
		declared uint32
		received int
	}{
		{"small", 4096, 4096},
		{"1MiB", 1 << 20, 1 << 20},
		{"32MiB", 32 << 20, 32 << 20},
		{"32MiB-plus-hash", (32 << 20) + 32, (32 << 20) + 32},
		{"truncated-32MiB", 32 << 20, 1 << 20},
		{"header-only-320MiB", MaxMessagePayload, 0},
	} {
		body := make([]byte, tc.received)
		for _, method := range readers {
			b.Run(tc.name+"/"+method.name, func(b *testing.B) {
				r := bytes.NewReader(body)
				b.SetBytes(int64(len(body)))
				b.ReportAllocs()
				for b.Loop() {
					r.Reset(body)
					got, err := method.read(r, tc.declared)
					if len(got) != len(body) || (err == nil) != (len(body) == int(tc.declared)) {
						b.Fatalf("unexpected read: %d, %v", len(got), err)
					}
					payloadBenchmarkSink = got
				}
			})
		}
	}
}
