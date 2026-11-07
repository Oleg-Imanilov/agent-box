package mcpgw

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
)

// sseEvent is one parsed Server-Sent Event (or a comment line).
type sseEvent struct {
	Comment string // set for comment/keepalive lines
	ID      string
	Event   string
	Retry   string
	Data    []byte
	HasData bool
}

var errEventTooLarge = errors.New("sse event too large")

// readSSE reads the next event. Comment lines are returned immediately as
// their own events so keepalives are not delayed. max bounds the size of one
// event.
func readSSE(r *bufio.Reader, max int) (sseEvent, error) {
	var (
		ev    sseEvent
		data  bytes.Buffer
		seen  bool
		total int
	)
	for {
		line, err := readLimitedLine(r, max)
		if err != nil {
			if errors.Is(err, io.EOF) && seen {
				// Incomplete trailing event: discard (never forward partial data).
				return sseEvent{}, io.EOF
			}
			return sseEvent{}, err
		}
		total += len(line) + 1
		if total > max {
			return sseEvent{}, errEventTooLarge
		}
		if line == "" { // dispatch
			if !seen {
				continue
			}
			if ev.HasData {
				ev.Data = bytes.TrimSuffix(data.Bytes(), []byte("\n"))
				ev.Data = append([]byte(nil), ev.Data...)
			}
			return ev, nil
		}
		if strings.HasPrefix(line, ":") {
			if !seen {
				return sseEvent{Comment: strings.TrimPrefix(line, ":")}, nil
			}
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		seen = true
		switch field {
		case "data":
			ev.HasData = true
			data.WriteString(value)
			data.WriteByte('\n')
		case "id":
			if !strings.ContainsRune(value, 0) {
				ev.ID = value
			}
		case "event":
			ev.Event = value
		case "retry":
			ev.Retry = value
		}
	}
}

func readLimitedLine(r *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return "", err
		}
		if sb.Len()+len(chunk) > max {
			return "", errEventTooLarge
		}
		sb.Write(chunk)
		if !isPrefix {
			return sb.String(), nil
		}
	}
}

// writeSSE serializes an event. Field values never contain newlines because
// they came from line-oriented parsing or from gateway-generated JSON.
func writeSSE(w io.Writer, ev sseEvent) error {
	var b bytes.Buffer
	if ev.Comment != "" || (ev.ID == "" && ev.Event == "" && ev.Retry == "" && !ev.HasData) {
		b.WriteString(":" + ev.Comment + "\n\n")
		_, err := w.Write(b.Bytes())
		return err
	}
	if ev.ID != "" {
		b.WriteString("id: " + ev.ID + "\n")
	}
	if ev.Event != "" {
		b.WriteString("event: " + ev.Event + "\n")
	}
	if ev.Retry != "" {
		b.WriteString("retry: " + ev.Retry + "\n")
	}
	if ev.HasData {
		for _, line := range bytes.Split(ev.Data, []byte("\n")) {
			b.WriteString("data: ")
			b.Write(line)
			b.WriteByte('\n')
		}
	}
	b.WriteByte('\n')
	_, err := w.Write(b.Bytes())
	return err
}
