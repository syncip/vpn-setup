package store

import "strings"

// Block-Prüfung: Ergebnis je Ziel (Domain) und Ausgang – dauerhaft gespeichert, damit bekannte Ziele
// nicht ständig neu geprüft werden müssen (Leute besuchen meist dieselben Seiten).
//
//	status: ok | captcha | blocked | error
//	fails:  Fehlversuche in Folge (Prüfung, Proxy, passive Erkennung) – ab 4 gilt der Ausgang als gesperrt
//	since:  seit wann der Status gilt; checked: letzte aktive Prüfung (0 = nur gemeldet, nie geprüft)

type BlockResult struct {
	Domain  string `json:"domain"`
	ExitID  int64  `json:"exit_id"`
	Status  string `json:"status"`
	Detail  string `json:"detail"`
	Checked int64  `json:"checked"`
	Fails   int    `json:"fails"`
	Since   int64  `json:"since"`
	Seen    int64  `json:"seen"` // zuletzt gemeldet (Fehler aus dem Verkehr)
}

// SetBlockResult speichert das Ergebnis einer aktiven Prüfung. ok setzt die Fehlversuche zurück,
// error zählt sie hoch, captcha/blocked zählen als sicher gesperrt.
func (s *Store) SetBlockResult(domain string, exitID int64, status, detail string, ts int64) (BlockResult, error) {
	domain = strings.ToLower(domain)
	prev, _ := s.BlockResult(domain, exitID)
	r := BlockResult{Domain: domain, ExitID: exitID, Status: status, Detail: detail, Checked: ts, Since: ts, Seen: prev.Seen}
	if prev.Status == status {
		r.Since = prev.Since
	}
	switch status {
	case "ok":
		r.Fails = 0
	case "error":
		r.Fails = prev.Fails + 1
	default:
		r.Fails = prev.Fails
	}
	_, err := s.db.Exec(`INSERT INTO block_results (domain, exit_id, status, detail, checked, fails, since, seen) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(domain, exit_id) DO UPDATE SET status=excluded.status, detail=excluded.detail, checked=excluded.checked,
		fails=excluded.fails, since=excluded.since`, r.Domain, r.ExitID, r.Status, r.Detail, r.Checked, r.Fails, r.Since, r.Seen)
	return r, err
}

// AddBlockFail meldet einen Fehlschlag aus dem Verkehr (Proxy, passive Erkennung) ohne aktive Prüfung.
// Ein bekanntes „ok“ bleibt bestehen, bis die Prüfung es bestätigt oder widerlegt; die Zahl steigt.
func (s *Store) AddBlockFail(domain string, exitID int64, detail string, ts int64) (BlockResult, error) {
	domain = strings.ToLower(domain)
	prev, err := s.BlockResult(domain, exitID)
	if err != nil {
		prev = BlockResult{Domain: domain, ExitID: exitID, Status: "error", Since: ts}
	}
	prev.Fails++
	prev.Seen = ts
	if prev.Status == "" {
		prev.Status, prev.Since = "error", ts
	}
	if prev.Status == "error" || prev.Status == "ok" {
		prev.Detail = detail
	}
	_, err = s.db.Exec(`INSERT INTO block_results (domain, exit_id, status, detail, checked, fails, since, seen) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(domain, exit_id) DO UPDATE SET fails=excluded.fails, seen=excluded.seen, detail=excluded.detail`,
		prev.Domain, prev.ExitID, prev.Status, prev.Detail, prev.Checked, prev.Fails, prev.Since, prev.Seen)
	return prev, err
}

// BlockResult: Ergebnis eines Ziels über einen Ausgang.
func (s *Store) BlockResult(domain string, exitID int64) (BlockResult, error) {
	var r BlockResult
	err := s.db.QueryRow(`SELECT domain, exit_id, status, detail, checked, fails, since, seen FROM block_results WHERE domain=? AND exit_id=?`,
		strings.ToLower(domain), exitID).Scan(&r.Domain, &r.ExitID, &r.Status, &r.Detail, &r.Checked, &r.Fails, &r.Since, &r.Seen)
	return r, err
}

// BlockResults: alle Ergebnisse (domain → Ausgang → Ergebnis).
func (s *Store) BlockResults() (map[string]map[int64]BlockResult, error) {
	rows, err := s.db.Query(`SELECT domain, exit_id, status, detail, checked, fails, since, seen FROM block_results`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[int64]BlockResult{}
	for rows.Next() {
		var r BlockResult
		if err := rows.Scan(&r.Domain, &r.ExitID, &r.Status, &r.Detail, &r.Checked, &r.Fails, &r.Since, &r.Seen); err != nil {
			return nil, err
		}
		if out[r.Domain] == nil {
			out[r.Domain] = map[int64]BlockResult{}
		}
		out[r.Domain][r.ExitID] = r
	}
	return out, rows.Err()
}

// DeleteBlockResults: Ergebnisse eines Ziels (domain) bzw. eines Ausgangs (exitID) löschen.
func (s *Store) DeleteBlockResults(domain string, exitID int64) error {
	var err error
	switch {
	case domain != "" && exitID != 0:
		_, err = s.db.Exec(`DELETE FROM block_results WHERE domain=? AND exit_id=?`, strings.ToLower(domain), exitID)
	case domain != "":
		_, err = s.db.Exec(`DELETE FROM block_results WHERE domain=?`, strings.ToLower(domain))
	case exitID != 0:
		_, err = s.db.Exec(`DELETE FROM block_results WHERE exit_id=?`, exitID)
	}
	return err
}

// PruneBlockResults: Ergebnisse, die lange weder geprüft noch gemeldet wurden.
func (s *Store) PruneBlockResults(before int64) error {
	_, err := s.db.Exec(`DELETE FROM block_results WHERE checked < ? AND seen < ?`, before, before)
	return err
}

// TopGroupDomains: meistgefragte Namen, deren Verkehr über eine Gruppe lief (DNS-Protokoll), ab since.
func (s *Store) TopGroupDomains(groupID, since int64, limit int) ([]string, error) {
	rows, err := s.db.Query(`SELECT name, COUNT(*) AS n FROM dns_log WHERE via = ? AND ts >= ? AND qtype = 1 AND action IN ('ok','cached')
		GROUP BY name ORDER BY n DESC LIMIT ?`, groupID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		var c int
		if err := rows.Scan(&n, &c); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
