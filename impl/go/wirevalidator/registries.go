// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package wirevalidator

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// SystemFrameMax is the highest frame-type value in the all-channel system
// band (registries/frame_types_reserved.csv rows 0x0001-0x000A; PING through
// FLOW_UPDATE; impl/go/frametypes.go). A frame type at or below this value
// carries the same meaning on every channel and is not looked up in
// frame_types_channel.csv. This mirrors scripts/validate-frame-types-channel.py's
// SYSTEM_FRAME_MAX constant exactly, so this package's notion of "system
// frame" matches the registry's own existing validator.
const SystemFrameMax = 0x000A

// chanFrameKey is the composite key frame_types_channel.csv is keyed by:
// (channel_id, frame_type).
type chanFrameKey struct {
	channel   uint16
	frameType uint16
}

// Registries holds the loaded allowlist data from registries/*.csv. It is
// built once via Load or LoadDefault and is safe for concurrent read-only
// use by multiple goroutines (all fields are populated at construction and
// never mutated afterward).
type Registries struct {
	// channels maps a registered channel_id to its name (channels.csv).
	channels map[uint16]string
	// systemFrames maps a registered all-channel system frame_type (<=
	// SystemFrameMax) to its name (frame_types_reserved.csv).
	systemFrames map[uint16]string
	// chanFrames records every registered (channel_id, frame_type) pair
	// (frame_types_channel.csv).
	chanFrames map[chanFrameKey]string
	// tlvTags maps an assigned TLV tag to its name (tlv_tags.csv rows whose
	// name is not the "(reserved)" placeholder).
	tlvTags map[uint16]string
	// errorCodes maps a registered (non-reserved) error code to its name
	// (registries/error_codes.csv rows 1-10; code 0 is reserved and
	// excluded, and the 0x000B-0x00FF range row is a range descriptor, not
	// a specific code, and is not a map entry).
	errorCodes map[uint8]string
}

// parseCodePoint parses a single hex or decimal code-point token (e.g.
// "0x0001" or "1") using base 0 (Go auto-detects the 0x/0X hex prefix,
// falling back to decimal), matching how registries/error_codes.csv mixes
// decimal (0-10) and hex (0x000B-0x00FF) representations in the same
// column. ok is false for a token that is not a single integer -- notably a
// hyphenated range ("0x0030-0x0034") or a non-numeric value -- so callers
// can skip range-descriptor rows without misparsing them.
func parseCodePoint(tok string) (val uint64, ok bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" || strings.Contains(tok, "-") {
		return 0, false
	}
	v, err := strconv.ParseUint(tok, 0, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// readCSVRows reads path as a CSV file and returns its header-mapped rows:
// each row is a map from header column name to that row's value in that
// column. This mirrors the header-mapped access pattern the project's own
// Python registry validators (scripts/validate-registries.py,
// scripts/validate-frame-types-channel.py) use via csv.DictReader, so a
// registry column reorder does not break this loader.
func readCSVRows(path string) ([]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("wirevalidator: open registry %s: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("wirevalidator: read header of %s: %w", path, err)
	}
	var rows []map[string]string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("wirevalidator: read row of %s: %w", path, err)
		}
		row := make(map[string]string, len(header))
		for i, col := range header {
			if i < len(rec) {
				row[col] = rec[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Load parses every registry this package consumes from root/registries/*.csv
// and returns a ready-to-use Registries. root must be the directory that
// directly contains a registries/ subdirectory (the N-PAMP repository root
// -- the same directory that holds PIN.json and MANIFEST.sha256). It fails
// closed: a missing file, an unreadable CSV, or a row that does not parse
// returns a non-nil error rather than silently loading a partial (and
// therefore falsely-permissive or falsely-restrictive) registry set.
func Load(root string) (*Registries, error) {
	reg := &Registries{
		channels:     map[uint16]string{},
		systemFrames: map[uint16]string{},
		chanFrames:   map[chanFrameKey]string{},
		tlvTags:      map[uint16]string{},
		errorCodes:   map[uint8]string{},
	}
	dir := filepath.Join(root, "registries")

	if err := reg.loadChannels(filepath.Join(dir, "channels.csv")); err != nil {
		return nil, err
	}
	if err := reg.loadSystemFrames(filepath.Join(dir, "frame_types_reserved.csv")); err != nil {
		return nil, err
	}
	if err := reg.loadChanFrames(filepath.Join(dir, "frame_types_channel.csv")); err != nil {
		return nil, err
	}
	if err := reg.loadTLVTags(filepath.Join(dir, "tlv_tags.csv")); err != nil {
		return nil, err
	}
	if err := reg.loadErrorCodes(filepath.Join(dir, "error_codes.csv")); err != nil {
		return nil, err
	}

	if len(reg.channels) == 0 || len(reg.systemFrames) == 0 || len(reg.chanFrames) == 0 ||
		len(reg.tlvTags) == 0 || len(reg.errorCodes) == 0 {
		return nil, fmt.Errorf("wirevalidator: loaded an empty registry set from %s (channels=%d systemFrames=%d chanFrames=%d tlvTags=%d errorCodes=%d)",
			dir, len(reg.channels), len(reg.systemFrames), len(reg.chanFrames), len(reg.tlvTags), len(reg.errorCodes))
	}
	return reg, nil
}

// DefaultRegistryRoot resolves the N-PAMP repository root relative to THIS
// source file's location by walking up from runtime.Caller(0): this file
// lives three directories below the repository root (impl/go/wirevalidator).
// This requires the source tree to be present on the running host, which
// holds for `go test`/`go run` from a checkout and for any deployment that
// ships the full repository -- the same resolution strategy and the same
// honest limitation as impl/go/schemaversion.DefaultRepoRoot. A binary
// distributed WITHOUT the source tree must call Load with an explicit root
// instead (e.g. from a deployment-time config path or environment variable
// the caller owns).
func DefaultRegistryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("wirevalidator: runtime.Caller could not resolve this source file's path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "registries", "channels.csv")); err != nil {
		return "", fmt.Errorf("wirevalidator: resolved root %s does not contain registries/channels.csv: %w", root, err)
	}
	return root, nil
}

// LoadDefault is Load(DefaultRegistryRoot()) -- the convenience entry point
// for code running from within this repository's own source tree (tests,
// the relay hook adapter's own default construction, etc.).
func LoadDefault() (*Registries, error) {
	root, err := DefaultRegistryRoot()
	if err != nil {
		return nil, err
	}
	return Load(root)
}

// loadChannels populates reg.channels from registries/channels.csv
// (columns: channel_id, name, purpose, min_profile, direction).
func (reg *Registries) loadChannels(path string) error {
	rows, err := readCSVRows(path)
	if err != nil {
		return err
	}
	for i, row := range rows {
		id, ok := parseCodePoint(row["channel_id"])
		if !ok || id > 0xFFFF {
			return fmt.Errorf("wirevalidator: %s row %d: unparseable channel_id %q", path, i, row["channel_id"])
		}
		name := row["name"]
		if name == "" {
			return fmt.Errorf("wirevalidator: %s row %d: empty name for channel_id %q", path, i, row["channel_id"])
		}
		reg.channels[uint16(id)] = name
	}
	return nil
}

// loadSystemFrames populates reg.systemFrames from
// registries/frame_types_reserved.csv (columns: frame_type, name,
// description), keeping only single-code-point rows with a real (non
// "(reserved)") name whose value is in the all-channel system band
// (1..SystemFrameMax). Frame type 0x0000 is "(reserved); MUST NOT be used"
// and is correctly excluded by the name filter. Rows above SystemFrameMax
// (e.g. the 0x0100-0x0103 Control-channel handshake rows, which recur in
// frame_types_channel.csv under their specific channel) and hyphenated
// range rows (e.g. "0x0030-0x0034") are intentionally skipped here: they
// are not all-channel system frames.
func (reg *Registries) loadSystemFrames(path string) error {
	rows, err := readCSVRows(path)
	if err != nil {
		return err
	}
	for _, row := range rows {
		ft, ok := parseCodePoint(row["frame_type"])
		if !ok {
			continue // a hyphenated range row; not a specific system frame type
		}
		if ft == 0 || ft > SystemFrameMax {
			continue
		}
		name := row["name"]
		if name == "" || name == "(reserved)" {
			continue
		}
		reg.systemFrames[uint16(ft)] = name
	}
	if len(reg.systemFrames) == 0 {
		return fmt.Errorf("wirevalidator: %s: no system frame types (0x0001-0x%04X) found", path, SystemFrameMax)
	}
	return nil
}

// loadChanFrames populates reg.chanFrames from
// registries/frame_types_channel.csv (columns: channel_id, channel_name,
// frame_type, name, go_const, go_file, band, description).
func (reg *Registries) loadChanFrames(path string) error {
	rows, err := readCSVRows(path)
	if err != nil {
		return err
	}
	for i, row := range rows {
		cid, ok := parseCodePoint(row["channel_id"])
		if !ok || cid > 0xFFFF {
			return fmt.Errorf("wirevalidator: %s row %d: unparseable channel_id %q", path, i, row["channel_id"])
		}
		ft, ok := parseCodePoint(row["frame_type"])
		if !ok || ft > 0xFFFF {
			return fmt.Errorf("wirevalidator: %s row %d: unparseable frame_type %q", path, i, row["frame_type"])
		}
		name := row["name"]
		if name == "" {
			return fmt.Errorf("wirevalidator: %s row %d: empty name for frame_type %q", path, i, row["frame_type"])
		}
		reg.chanFrames[chanFrameKey{channel: uint16(cid), frameType: uint16(ft)}] = name
	}
	return nil
}

// loadTLVTags populates reg.tlvTags from registries/tlv_tags.csv (columns:
// tag, name, length, description), keeping only single-code-point rows with
// a real (non "(reserved)") name. Both companion-reserved placeholder rows
// (e.g. 0x10, 0x14) and the forward-incompatible-extension-point range row
// (0x8000-0xFFFF) are intentionally excluded from the allowlist: neither
// carries defined semantics today, so this validator's fail-closed posture
// (package doc) treats both the same as any other unassigned tag.
func (reg *Registries) loadTLVTags(path string) error {
	rows, err := readCSVRows(path)
	if err != nil {
		return err
	}
	for _, row := range rows {
		tag, ok := parseCodePoint(row["tag"])
		if !ok || tag > 0xFFFF {
			continue // a hyphenated range row (e.g. "0x8000-0xFFFF")
		}
		name := row["name"]
		if name == "" || name == "(reserved)" {
			continue
		}
		reg.tlvTags[uint16(tag)] = name
	}
	if len(reg.tlvTags) == 0 {
		return fmt.Errorf("wirevalidator: %s: no assigned TLV tags found", path)
	}
	return nil
}

// loadErrorCodes populates reg.errorCodes from registries/error_codes.csv
// (columns: code, name, reaction, condition), keeping only single-integer
// rows (decimal, as the registered codes 1-10 are written) with a real
// (non "(reserved)") name. Code 0 ("(reserved); MUST NOT be sent") is
// correctly excluded by the name filter, and the hyphenated-hex range row
// (0x000B-0x00FF, unassigned) is skipped by parseCodePoint.
func (reg *Registries) loadErrorCodes(path string) error {
	rows, err := readCSVRows(path)
	if err != nil {
		return err
	}
	for _, row := range rows {
		code, ok := parseCodePoint(row["code"])
		if !ok || code > 0xFF {
			continue // a hyphenated range row, or (defensively) out of the u8 domain
		}
		name := row["name"]
		if name == "" || name == "(reserved)" {
			continue
		}
		reg.errorCodes[uint8(code)] = name
	}
	if len(reg.errorCodes) == 0 {
		return fmt.Errorf("wirevalidator: %s: no assigned error codes found", path)
	}
	return nil
}
