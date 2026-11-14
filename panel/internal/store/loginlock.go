package store

// LoginLock: gesperrte Adresse bzw. gesperrtes Netz für die Anmeldung am Panel.
// Net ist eine einzelne IPv4-Adresse („203.0.113.7“) oder ein Präfix („2001:db8:1:2::/64“).
type LoginLock struct {
	Net     string `json:"net"`
	Until   int64  `json:"until"`   // Unix-Zeit, 0 = dauerhaft
	Manual  bool   `json:"manual"`  // von Hand gesperrt
	Strikes int    `json:"strikes"` // wievielte automatische Sperre in Folge
	Reason  string `json:"reason"`
	Created int64  `json:"created"`
}

// LoginLocks: alle Einträge (auch abgelaufene, damit die Verlängerung bei Wiederholung greift).
func (s *Store) LoginLocks() ([]*LoginLock, error) {
	rows, err := s.db.Query(`SELECT net, until, manual, strikes, reason, created FROM login_locks ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*LoginLock
	for rows.Next() {
		var l LoginLock
		var m int
		if err := rows.Scan(&l.Net, &l.Until, &m, &l.Strikes, &l.Reason, &l.Created); err != nil {
			return nil, err
		}
		l.Manual = m == 1
		out = append(out, &l)
	}
	return out, rows.Err()
}

func (s *Store) PutLoginLock(l *LoginLock) error {
	if l.Created == 0 {
		l.Created = now()
	}
	_, err := s.db.Exec(`INSERT INTO login_locks (net, until, manual, strikes, reason, created) VALUES (?,?,?,?,?,?)
		ON CONFLICT(net) DO UPDATE SET until=excluded.until, manual=excluded.manual, strikes=excluded.strikes, reason=excluded.reason, created=excluded.created`,
		l.Net, l.Until, b2i(l.Manual), l.Strikes, l.Reason, l.Created)
	return err
}

func (s *Store) DeleteLoginLock(net string) error {
	_, err := s.db.Exec(`DELETE FROM login_locks WHERE net=?`, net)
	return err
}

// PruneLoginLocks: automatische Sperren, die seit mehr als einem Tag abgelaufen sind, entfernen.
func (s *Store) PruneLoginLocks() {
	_, _ = s.db.Exec(`DELETE FROM login_locks WHERE manual=0 AND until>0 AND until < ?`, now()-86400)
}
