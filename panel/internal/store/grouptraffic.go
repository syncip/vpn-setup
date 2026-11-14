package store

// Verkehr über Ausgangsgruppen je Stunde: der Verkehr eines Ausgangs zählt für die Gruppen,
// die ihn gerade als aktiven Ausgang nutzen (Grundlage für Gruppen-Limits).

func (s *Store) AddGroupTraffic(groupID, ts, up, down int64) error {
	hour := ts - ts%3600
	_, err := s.db.Exec(`INSERT INTO group_traffic (group_id, hour, up, down) VALUES (?,?,?,?)
		ON CONFLICT(group_id, hour) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, groupID, hour, up, down)
	return err
}

// DeleteGroupTraffic: beim Löschen einer Gruppe.
func (s *Store) DeleteGroupTraffic(groupID int64) error {
	_, err := s.db.Exec(`DELETE FROM group_traffic WHERE group_id = ?`, groupID)
	return err
}

// GroupTraffic: Summen je Gruppe ab since (0 = alles).
func (s *Store) GroupTraffic(since int64) (map[int64]ExitTotals, error) {
	rows, err := s.db.Query(`SELECT group_id, SUM(up), SUM(down) FROM group_traffic WHERE hour >= ? GROUP BY group_id`, since-since%3600)
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
