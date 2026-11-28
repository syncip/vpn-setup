package store

// Verkehr je Stunde (Zugänge und Ausgänge).

// ---------- Traffic-Verlauf ----------

// AddTraffic bucht Traffic stundenweise (für Diagramme).
func (s *Store) AddTraffic(peerID, userID, serverID, ts, up, down int64) error {
	hour := ts - ts%3600
	_, err := s.db.Exec(`INSERT INTO traffic (peer_id, user_id, server_id, hour, up, down) VALUES (?,?,?,?,?,?)
		ON CONFLICT(peer_id, hour) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, peerID, userID, serverID, hour, up, down)
	return err
}

// TrafficSeries liefert Summen pro Zeitfenster (bucket Sekunden) ab since.
// filter: "" | "user" | "server" | "peer" mit id.
func (s *Store) TrafficSeries(since, until, bucket int64, filter string, id int64) ([]TrafficPoint, error) {
	if bucket <= 0 {
		bucket = 3600
	}
	where := "hour >= ? AND hour < ?"
	args := []any{bucket, bucket, since - since%3600, until}
	switch filter {
	case "user":
		where += " AND user_id=?"
		args = append(args, id)
	case "server":
		where += " AND server_id=?"
		args = append(args, id)
	case "peer":
		where += " AND peer_id=?"
		args = append(args, id)
	}
	rows, err := s.db.Query(`SELECT (hour/?)*? AS b, SUM(up), SUM(down) FROM traffic WHERE `+where+` GROUP BY b ORDER BY b`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficPoint
	for rows.Next() {
		var p TrafficPoint
		if err := rows.Scan(&p.TS, &p.Up, &p.Down); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// TrafficSum liefert Summen seit since (gesamt oder pro Nutzer).
func (s *Store) TrafficSum(since int64) (up, down int64, err error) {
	err = s.db.QueryRow(`SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM traffic WHERE hour >= ?`, since).Scan(&up, &down)
	return
}

// TrafficByUser liefert die Summe pro Nutzer seit since.
func (s *Store) TrafficByUser(since int64) (map[int64][2]int64, error) {
	rows, err := s.db.Query(`SELECT user_id, SUM(up), SUM(down) FROM traffic WHERE hour >= ? GROUP BY user_id`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int64][2]int64{}
	for rows.Next() {
		var id, u, d int64
		if err := rows.Scan(&id, &u, &d); err != nil {
			return nil, err
		}
		m[id] = [2]int64{u, d}
	}
	return m, rows.Err()
}

func (s *Store) PruneTraffic(before int64) error {
	_, err := s.db.Exec(`DELETE FROM traffic WHERE hour < ?`, before)
	if err == nil {
		_, err = s.db.Exec(`DELETE FROM exit_traffic WHERE hour < ?`, before)
	}
	if err == nil {
		_, err = s.db.Exec(`DELETE FROM group_traffic WHERE hour < ?`, before)
	}
	if err == nil {
		_, err = s.db.Exec(`DELETE FROM smart_traffic WHERE hour < ?`, before)
	}
	return err
}

// ---------- Verkehr über Ausgänge ----------

// AddExitTraffic zählt Verkehr eines Ausgangs zur Stunde von ts.
func (s *Store) AddExitTraffic(exitID, ts, up, down int64) error {
	hour := ts - ts%3600
	_, err := s.db.Exec(`INSERT INTO exit_traffic (exit_id, hour, up, down) VALUES (?,?,?,?)
		ON CONFLICT(exit_id, hour) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, exitID, hour, up, down)
	return err
}

// DeleteExitTraffic: beim Löschen eines Ausgangs.
func (s *Store) DeleteExitTraffic(exitID int64) error {
	_, err := s.db.Exec(`DELETE FROM exit_traffic WHERE exit_id = ?`, exitID)
	return err
}

// ExitTotals: Summen je Ausgang ab since (0 = alles).
type ExitTotals struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

func (s *Store) ExitTraffic(since int64) (map[int64]ExitTotals, error) {
	rows, err := s.db.Query(`SELECT exit_id, SUM(up), SUM(down) FROM exit_traffic WHERE hour >= ? GROUP BY exit_id`, since-since%3600)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]ExitTotals{}
	for rows.Next() {
		var id int64
		var t ExitTotals
		if err := rows.Scan(&id, &t.Up, &t.Down); err != nil {
			return nil, err
		}
		out[id] = t
	}
	return out, rows.Err()
}

// ExitTrafficRange: stündliche Werte [Stunde, Ausgang, hoch, runter] in [since, until).
func (s *Store) ExitTrafficRange(since, until int64) ([][4]int64, error) {
	rows, err := s.db.Query(`SELECT hour, exit_id, up, down FROM exit_traffic WHERE hour >= ? AND hour < ? ORDER BY hour`, since-since%3600, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := [][4]int64{}
	for rows.Next() {
		var r [4]int64
		if err := rows.Scan(&r[0], &r[1], &r[2], &r[3]); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
