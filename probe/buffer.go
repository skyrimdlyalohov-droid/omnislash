package probe

import (
	"io"
	"sync"
)

// BufferSize is the fixed scratch-buffer size used by the probe reader. It is
// deliberately a power-of-two page multiple: large enough for normal headers
// and small bodies, small enough that a pool of idle buffers is cheap.
const BufferSize = 32 << 10

var probeBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, BufferSize)
		return &buf
	},
}

// AcquireBuffer returns a zeroed 32 KiB scratch buffer. Callers must pair it
// with ReleaseBuffer. The returned slice has length 0 and capacity BufferSize.
func AcquireBuffer() []byte {
	buf := probeBufferPool.Get().(*[]byte)
	return (*buf)[:0]
}

// ReleaseBuffer returns buf to the pool after wiping every byte. The wipe is
// not an optimization: a stale H2 frame or smuggled request left in a reused
// buffer would be appended to the next request and destroy byte transparency
// (payload bleeding). Buffers with an unexpected capacity are dropped instead
// of poisoning the pool.
func ReleaseBuffer(buf []byte) {
	if cap(buf) < BufferSize {
		return
	}
	full := buf[:BufferSize]
	clear(full)
	scratch := full
	probeBufferPool.Put(&scratch)
}

// copyN is io.CopyN with a pooled scratch buffer. It returns io.EOF when the
// source ends before n bytes, exactly like io.CopyN, so a truncated response
// is never mistaken for a complete one.
func copyN(dst io.Writer, src io.Reader, n int64) (int64, error) {
	if n <= 0 {
		return 0, nil
	}
	scratch := AcquireBuffer()
	scratch = scratch[:cap(scratch)]
	defer ReleaseBuffer(scratch)

	var written int64
	for written < n {
		chunk := scratch
		if remaining := n - written; int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		read, readErr := src.Read(chunk)
		if read > 0 {
			wrote, writeErr := dst.Write(chunk[:read])
			written += int64(wrote)
			if writeErr != nil {
				return written, writeErr
			}
			if wrote != read {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if readErr == io.EOF && written < n {
				return written, io.EOF
			}
			return written, readErr
		}
	}
	return written, nil
}
