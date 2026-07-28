package service

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// marshal renders a wire value. The wire types are all marshal-safe; a failure
// here is a programming error surfaced as a wire error rather than a panic.
func marshal(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"error":"service: response cannot be encoded"}`)
	}
	return data
}

// unmarshalStrict decodes refusing unknown fields — the same strictness the
// milestone-1 surface had, so shape drift fails loudly on both sides.
func unmarshalStrict(data []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("service: invalid request: %w", err)
	}
	return nil
}
