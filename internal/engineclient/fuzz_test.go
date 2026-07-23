package engineclient

import (
	"strings"
	"testing"
)

// FuzzReadNDJSONStream fuzzer targets the NDJSON parsing loop in readNDJSONStream.
func FuzzReadNDJSONStream(f *testing.F) {
	// Seed corpus with valid and invalid NDJSON examples
	f.Add(`{"protocol_version":"rygnal.engine.v1","request_id":"req-1","timestamp":"2026-06-15T00:00:00.000Z","event":"engine.started","ok":true,"status":"starting","data":{},"error":null}`)
	f.Add(`{"protocol_version":"rygnal.engine.v1","request_id":"req-1","timestamp":"2026-06-15T00:00:00.000Z","event":"run.completed","ok":true,"status":"completed","data":{"status":"completed"},"error":null}`)
	f.Add(`{"protocol_version":"rygnal.engine.v1","request_id":"fuzz","event":"test"}`)
	f.Add("not-json\n")
	f.Add(`{"protocol_version":"wrong.version"}`)
	f.Add("")

	f.Fuzz(func(t *testing.T, data string) {
		r := strings.NewReader(data)
		_, _ = readNDJSONStream(r, func(rawLine string, event EngineEvent) error {
			// Callback function simply processes the event
			_ = event.RequestID
			_ = event.Status
			return nil
		})
	})
}

// FuzzBoundedBuffer fuzzer targets the bounded stderr buffer write mechanics.
func FuzzBoundedBuffer(f *testing.F) {
	f.Add([]byte("simple log message"), 10)
	f.Add([]byte(""), 0)
	f.Add([]byte("a very long log entry that exceeds target size limits"), 5)

	f.Fuzz(func(t *testing.T, input []byte, limit int) {
		if limit < 0 || limit > 10000 {
			return
		}
		buf := newBoundedBuffer(limit)
		_, _ = buf.Write(input)
		_ = buf.String()
	})
}

// FuzzUpsertEnv fuzzer targets environment variables manipulation helper function.
func FuzzUpsertEnv(f *testing.F) {
	f.Add("PATH=/usr/bin", "PYTHONPATH", "/tmp/src")
	f.Add("", "KEY", "VALUE")

	f.Fuzz(func(t *testing.T, initialEnv, key, value string) {
		var env []string
		if initialEnv != "" {
			env = []string{initialEnv}
		}
		_ = upsertEnv(env, key, value)
	})
}
