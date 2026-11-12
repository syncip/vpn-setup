package store

import (
	"strings"
)

// DNSEntry: eine DNS-Anfrage im Protokoll des Panel-DNS.
type DNSEntry struct {
	ID     int64  `json:"id"`
	TS     int64  `json:"ts"`
	PeerID int64  `json:"peer_id"`
	UserID int64  `json:"user_id"`
	Client string `json:"client"` // Absenderadresse
	Name   string `json:"name"`
	QType  int    `json:"qtype"`
	Action string `json:"action"` // ok | cached | blocked | rewritten | error
	RCode  int    `json:"rcode"`
	MS     int    `json:"ms"`
	Via    int64  `json:"via"`    // Ausgangsgruppe (0 = direkt)
	Detail string `json:"detail"` // z. B. Liste oder Regel, die gesperrt hat
}

// AddDNSLog schreibt mehrere Einträge in einem Rutsch.
func (s *Store) AddDNSLog(es []DNSEntry) error {
	if len(es) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	st, err := tx.Prepare(`INSERT INTO dns_log (ts, peer_id, user_id, client, name, qtype, action, rcode, ms, via, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, e := range es {
		if _, err := st.Exec(e.TS, e.PeerID, e.UserID, e.Client, e.Name, e.QType, e.Action, e.RCode, e.MS, e.Via, e.Detail); err != nil {
			st.Close()
			tx.Rollback()
			return err
		}
	}
	st.Close()
	return tx.Commit()
}

// PruneDNSLog löscht Einträge vor dem Zeitpunkt.
func (s *Store) PruneDNSLog(before int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM dns_log WHERE ts < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DNSLogFilter: Auswahl für die Protokoll-Ansicht.
type DNSLogFilter struct {
	Query  string // Teil des Namens
	PeerID int64
	UserID int64
	Action string // blocked | ok | … ; leer = alle
	Before int64  // nur Einträge mit kleinerer ID (Blättern)
	Limit  int
}

func (f DNSLogFilter) where() (string, []any) {
	var w []string
	var args []any
	if f.Query != "" {
		w = append(w, `name LIKE ? ESCAPE '\'`)
		q := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(f.Query))
		args = append(args, "%"+q+"%")
	}
	if f.PeerID != 0 {
		w = append(w, `peer_id = ?`)
		args = append(args, f.PeerID)
	}
	if f.UserID != 0 {
		w = append(w, `user_id = ?`)
		args = append(args, f.UserID)
	}
	if f.Action != "" {
		if f.Action == "ok" {
			w = append(w, `action IN ('ok','cached')`)
		} else {
			w = append(w, `action = ?`)
			args = append(args, f.Action)
		}
	}
	if f.Before > 0 {
		w = append(w, `id < ?`)
		args = append(args, f.Before)
	}
	if len(w) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(w, " AND "), args
}

// DNSLog liefert die neuesten Einträge passend zum Filter.
func (s *Store) DNSLog(f DNSLogFilter) ([]DNSEntry, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	where, args := f.where()
	rows, err := s.db.Query(`SELECT id, ts, peer_id, user_id, client, name, qtype, action, rcode, ms, via, detail FROM dns_log`+where+
		` ORDER BY id DESC LIMIT ?`, append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSEntry{}
	for rows.Next() {
		var e DNSEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.PeerID, &e.UserID, &e.Client, &e.Name, &e.QType, &e.Action, &e.RCode, &e.MS, &e.Via, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DNSCount: Name bzw. Gerät mit Anzahl.
type DNSCount struct {
	Name   string `json:"name,omitempty"`
	PeerID int64  `json:"peer_id,omitempty"`
	Client string `json:"client,omitempty"`
	Count  int    `json:"count"`
	Bl     int    `json:"blocked,omitempty"`
}

// DNSStats: Auswertung ab einem Zeitpunkt.
type DNSStats struct {
	Total      int        `json:"total"`
	Blocked    int        `json:"blocked"`
	Rewritten  int        `json:"rewritten"`
	Cached     int        `json:"cached"`
	Errors     int        `json:"errors"`
	AvgMS      float64    `json:"avg_ms"`
	Hours      [][3]int64 `json:"hours"` // [Stunde (Unix), Anfragen, gesperrt]
	TopDomains []DNSCount `json:"top_domains"`
	TopBlocked []DNSCount `json:"top_blocked"`
	TopClients []DNSCount `json:"top_clients"`
}

// DNSStats wertet das Protokoll aus (peerID 0 = alle Geräte).
func (s *Store) DNSStats(since, peerID int64) (*DNSStats, error) {
	st := &DNSStats{Hours: [][3]int64{}, TopDomains: []DNSCount{}, TopBlocked: []DNSCount{}, TopClients: []DNSCount{}}
	cond, args := ` WHERE ts >= ?`, []any{since}
	if peerID != 0 {
		cond += ` AND peer_id = ?`
		args = append(args, peerID)
	}
	var avg *float64
	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(action='blocked'),0), COALESCE(SUM(action='rewritten'),0), COALESCE(SUM(action='cached'),0),
		COALESCE(SUM(action='error'),0), AVG(CASE WHEN action='ok' THEN ms END) FROM dns_log`+cond, args...).
		Scan(&st.Total, &st.Blocked, &st.Rewritten, &st.Cached, &st.Errors, &avg); err != nil {
		return nil, err
	}
	if avg != nil {
		st.AvgMS = *avg
	}
	rows, err := s.db.Query(`SELECT ts/3600*3600 AS h, COUNT(*), SUM(action='blocked') FROM dns_log`+cond+` GROUP BY h ORDER BY h`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h [3]int64
		if err := rows.Scan(&h[0], &h[1], &h[2]); err != nil {
			rows.Close()
			return nil, err
		}
		st.Hours = append(st.Hours, h)
	}
	rows.Close()
	top := func(q string, scan func(*DNSCount) []any, out *[]DNSCount) error {
		rows, err := s.db.Query(q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c DNSCount
			if err := rows.Scan(scan(&c)...); err != nil {
				return err
			}
			*out = append(*out, c)
		}
		return rows.Err()
	}
	nameScan := func(c *DNSCount) []any { return []any{&c.Name, &c.Count} }
	if err := top(`SELECT name, COUNT(*) AS n FROM dns_log`+cond+` AND action != 'blocked' GROUP BY name ORDER BY n DESC LIMIT 15`, nameScan, &st.TopDomains); err != nil {
		return nil, err
	}
	if err := top(`SELECT name, COUNT(*) AS n FROM dns_log`+cond+` AND action = 'blocked' GROUP BY name ORDER BY n DESC LIMIT 15`, nameScan, &st.TopBlocked); err != nil {
		return nil, err
	}
	if err := top(`SELECT peer_id, MAX(client), COUNT(*) AS n, SUM(action='blocked') FROM dns_log`+cond+` GROUP BY peer_id ORDER BY n DESC LIMIT 15`,
		func(c *DNSCount) []any { return []any{&c.PeerID, &c.Client, &c.Count, &c.Bl} }, &st.TopClients); err != nil {
		return nil, err
	}
	return st, nil
}
