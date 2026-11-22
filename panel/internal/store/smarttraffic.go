package store

// SmartDNS-Verkehr je Stunde (für die Verlaufsgrafiken):
//   kind 0 = VPN-Geräte über SmartDNS-Weiterleitungen (Teil des Verkehrs der Zugänge, nft-Zähler)
//   kind 1 = Geräte ohne VPN über den SmartDNS-Proxy (kommt im Verkehr der Zugänge nicht vor)

const (
	SmartVPN   = 0
	SmartProxy = 1
)

// AddSmartTraffic bucht SmartDNS-Verkehr stundenweise.
func (s *Store) AddSmartTraffic(kind int, ts, up, down int64) error {
	if up <= 0 && down <= 0 {
		return nil
	}
	hour := ts - ts%3600
	_, err := s.db.Exec(`INSERT INTO smart_traffic (hour, kind, up, down) VALUES (?,?,?,?)
		ON CONFLICT(hour, kind) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, hour, kind, up, down)
	return err
}

// SmartTrafficPoint: SmartDNS-Verkehr eines Zeitfensters.
type SmartTrafficPoint struct {
	VUp, VDown, PUp, PDown int64
}

// SmartTrafficSeries: Summen je Zeitfenster (bucket Sekunden), Schlüssel = Beginn des Fensters.
func (s *Store) SmartTrafficSeries(since, until, bucket int64) (map[int64]*SmartTrafficPoint, error) {
	if bucket <= 0 {
		bucket = 3600
	}
	rows, err := s.db.Query(`SELECT (hour/?)*? AS b, kind, SUM(up), SUM(down) FROM smart_traffic WHERE hour >= ? AND hour < ? GROUP BY b, kind`,
		bucket, bucket, since-since%3600, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]*SmartTrafficPoint{}
	for rows.Next() {
		var b, up, down int64
		var kind int
		if err := rows.Scan(&b, &kind, &up, &down); err != nil {
			return nil, err
		}
		p := out[b]
		if p == nil {
			p = &SmartTrafficPoint{}
			out[b] = p
		}
		if kind == SmartProxy {
			p.PUp, p.PDown = p.PUp+up, p.PDown+down
		} else {
			p.VUp, p.VDown = p.VUp+up, p.VDown+down
		}
	}
	return out, rows.Err()
}

// SmartTrafficSum: Summen seit since (kind wie oben).
func (s *Store) SmartTrafficSum(kind int, since int64) (up, down int64, err error) {
	err = s.db.QueryRow(`SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM smart_traffic WHERE kind = ? AND hour >= ?`,
		kind, since-since%3600).Scan(&up, &down)
	return
}
