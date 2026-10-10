package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Summary counts records so the editor can classify the log without loading
// every command and its output. Host names are aliases the operator already
// sees; commands and output are not included.
type Summary struct {
	Total    int            `json:"total"`
	Decision map[string]int `json:"decision"`
	Type     map[string]int `json:"type"`
	Host     map[string]int `json:"host"`
	Today    int            `json:"today"`
	Last24h  int            `json:"last_24h"`
	Last7d   int            `json:"last_7d"`
	Last30d  int            `json:"last_30d"`
}

type summaryLine struct {
	Time     time.Time `json:"time"`
	Type     string    `json:"type"`
	Host     string    `json:"host"`
	Decision string    `json:"decision"`
}

// Summarize counts the log. now is the clock for the rolling windows. today
// is the start of the operator's local day; a zero today leaves Today at 0.
// A missing file is an empty summary, same as Query.
func Summarize(path string, now, today time.Time) (Summary, error) {
	out := Summary{
		Decision: map[string]int{},
		Type:     map[string]int{},
		Host:     map[string]int{},
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return Summary{}, fmt.Errorf("audit: %w", err)
	}
	defer file.Close()

	day := now.Add(-24 * time.Hour)
	week := now.AddDate(0, 0, -7)
	month := now.AddDate(0, 0, -30)

	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r summaryLine
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		out.Total++
		if r.Decision != "" {
			out.Decision[r.Decision]++
		}
		if r.Type != "" {
			out.Type[r.Type]++
		}
		if r.Host != "" {
			out.Host[r.Host]++
		}
		if !today.IsZero() && !r.Time.Before(today) {
			out.Today++
		}
		if !r.Time.Before(day) {
			out.Last24h++
		}
		if !r.Time.Before(week) {
			out.Last7d++
		}
		if !r.Time.Before(month) {
			out.Last30d++
		}
	}
	if err := sc.Err(); err != nil {
		return Summary{}, fmt.Errorf("audit: %w", err)
	}
	return out, nil
}
