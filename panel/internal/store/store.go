package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("nicht gefunden")

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: eine Schreibverbindung, vermeidet SQLITE_BUSY
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("Datenbank-Migration: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().Unix() }

var migrations = []string{
	`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
	 CREATE TABLE servers (id INTEGER PRIMARY KEY, name TEXT NOT NULL, protocol TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
	   settings TEXT NOT NULL DEFAULT '{}', state TEXT NOT NULL DEFAULT '{}', created INTEGER NOT NULL);
	 CREATE TABLE plans (id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', limits TEXT NOT NULL DEFAULT '{}', created INTEGER NOT NULL);
	 CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, note TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
	   plan_id INTEGER REFERENCES plans(id) ON DELETE SET NULL, limits TEXT, expires_at INTEGER NOT NULL DEFAULT 0, sub_token TEXT NOT NULL UNIQUE,
	   period_start INTEGER NOT NULL DEFAULT 0, period_up INTEGER NOT NULL DEFAULT 0, period_down INTEGER NOT NULL DEFAULT 0,
	   total_up INTEGER NOT NULL DEFAULT 0, total_down INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0,
	   status TEXT NOT NULL DEFAULT 'ok', status_reason TEXT NOT NULL DEFAULT '', rate_down REAL NOT NULL DEFAULT 0, rate_up REAL NOT NULL DEFAULT 0,
	   created INTEGER NOT NULL);
	 CREATE TABLE peers (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	   server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE, name TEXT NOT NULL, kind TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
	   settings TEXT NOT NULL DEFAULT '{}', secrets TEXT NOT NULL DEFAULT '{}', total_up INTEGER NOT NULL DEFAULT 0, total_down INTEGER NOT NULL DEFAULT 0,
	   last_rx INTEGER NOT NULL DEFAULT 0, last_tx INTEGER NOT NULL DEFAULT 0, handshake INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0,
	   endpoint TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL);
	 CREATE INDEX peers_user ON peers(user_id);
	 CREATE INDEX peers_server ON peers(server_id);
	 CREATE TABLE traffic (peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE, user_id INTEGER NOT NULL, server_id INTEGER NOT NULL,
	   hour INTEGER NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (peer_id, hour));
	 CREATE INDEX traffic_hour ON traffic(hour);
	 CREATE INDEX traffic_user ON traffic(user_id, hour);
	 CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, pass_hash TEXT NOT NULL, totp_secret TEXT NOT NULL DEFAULT '',
	   totp_enabled INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
	 CREATE TABLE sessions (id TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE, created INTEGER NOT NULL,
	   expires INTEGER NOT NULL, last_used INTEGER NOT NULL, ip TEXT NOT NULL DEFAULT '', agent TEXT NOT NULL DEFAULT '');
	 CREATE TABLE events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, level TEXT NOT NULL, msg TEXT NOT NULL);`,
	// Ausgänge (externe VPNs), Ausgangsgruppen, IP-Listen
	`CREATE TABLE objects (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
	   data TEXT NOT NULL DEFAULT '{}', secrets TEXT NOT NULL DEFAULT '{}', created INTEGER NOT NULL);
	 CREATE INDEX objects_kind ON objects(kind);`,
	// DNS-Protokoll des Panel-DNS
	`CREATE TABLE dns_log (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, peer_id INTEGER NOT NULL DEFAULT 0, user_id INTEGER NOT NULL DEFAULT 0,
	   client TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, qtype INTEGER NOT NULL, action TEXT NOT NULL, rcode INTEGER NOT NULL DEFAULT 0,
	   ms INTEGER NOT NULL DEFAULT 0, via INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT '');
	 CREATE INDEX dns_log_ts ON dns_log(ts);
	 CREATE INDEX dns_log_peer ON dns_log(peer_id, ts);`,
	// Verkehr über die Ausgänge (externe VPNs) je Stunde
	`CREATE TABLE exit_traffic (exit_id INTEGER NOT NULL, hour INTEGER NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
	   PRIMARY KEY (exit_id, hour));
	 CREATE INDEX exit_traffic_hour ON exit_traffic(hour);`,
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(v),0) FROM schema_version`).Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.Exec(`INSERT INTO schema_version (v) VALUES (?)`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ---------- Hilfsfunktionen ----------

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func fromJSON(s string, v any) {
	if s == "" {
		return
	}
	_ = json.Unmarshal([]byte(s), v)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

type scanner interface{ Scan(...any) error }

// ---------- Einstellungen ----------

func (s *Store) GetSetting(key, def string) string {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) AllSettings() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, rows.Err()
}

// ---------- Server ----------

const serverCols = `id, name, protocol, enabled, settings, state, created`

func scanServer(r scanner) (*Server, error) {
	var sv Server
	var en int
	var set, st string
	if err := r.Scan(&sv.ID, &sv.Name, &sv.Protocol, &en, &set, &st, &sv.Created); err != nil {
		return nil, err
	}
	sv.Enabled = en == 1
	sv.Settings, sv.State = M{}, M{}
	fromJSON(set, &sv.Settings)
	fromJSON(st, &sv.State)
	return &sv, nil
}

func (s *Store) Servers() ([]*Server, error) {
	rows, err := s.db.Query(`SELECT ` + serverCols + ` FROM servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Server
	for rows.Next() {
		sv, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}

func (s *Store) Server(id int64) (*Server, error) {
	sv, err := scanServer(s.db.QueryRow(`SELECT `+serverCols+` FROM servers WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sv, err
}

func (s *Store) SaveServer(sv *Server) error {
	if sv.Settings == nil {
		sv.Settings = M{}
	}
	if sv.State == nil {
		sv.State = M{}
	}
	if sv.ID == 0 {
		sv.Created = now()
		res, err := s.db.Exec(`INSERT INTO servers (name, protocol, enabled, settings, state, created) VALUES (?,?,?,?,?,?)`,
			sv.Name, sv.Protocol, b2i(sv.Enabled), toJSON(sv.Settings), toJSON(sv.State), sv.Created)
		if err != nil {
			return err
		}
		sv.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := s.db.Exec(`UPDATE servers SET name=?, protocol=?, enabled=?, settings=?, state=? WHERE id=?`,
		sv.Name, sv.Protocol, b2i(sv.Enabled), toJSON(sv.Settings), toJSON(sv.State), sv.ID)
	return err
}

func (s *Store) DeleteServer(id int64) error {
	_, err := s.db.Exec(`DELETE FROM servers WHERE id=?`, id)
	return err
}

// ---------- Tarife ----------

func (s *Store) Plans() ([]*Plan, error) {
	rows, err := s.db.Query(`SELECT id, name, description, limits, created FROM plans ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Plan
	for rows.Next() {
		var p Plan
		var lim string
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &lim, &p.Created); err != nil {
			return nil, err
		}
		fromJSON(lim, &p.Limits)
		out = append(out, &p)
	}
	return out, rows.Err()
}

func (s *Store) Plan(id int64) (*Plan, error) {
	var p Plan
	var lim string
	err := s.db.QueryRow(`SELECT id, name, description, limits, created FROM plans WHERE id=?`, id).Scan(&p.ID, &p.Name, &p.Description, &lim, &p.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	fromJSON(lim, &p.Limits)
	return &p, err
}

func (s *Store) SavePlan(p *Plan) error {
	if p.ID == 0 {
		p.Created = now()
		res, err := s.db.Exec(`INSERT INTO plans (name, description, limits, created) VALUES (?,?,?,?)`, p.Name, p.Description, toJSON(p.Limits), p.Created)
		if err != nil {
			return err
		}
		p.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := s.db.Exec(`UPDATE plans SET name=?, description=?, limits=? WHERE id=?`, p.Name, p.Description, toJSON(p.Limits), p.ID)
	return err
}

func (s *Store) DeletePlan(id int64) error {
	_, err := s.db.Exec(`DELETE FROM plans WHERE id=?`, id)
	return err
}

// ---------- Nutzer ----------

const userCols = `id, name, note, enabled, plan_id, limits, expires_at, sub_token, period_start, period_up, period_down,
	total_up, total_down, last_seen, status, status_reason, rate_down, rate_up, created`

func scanUser(r scanner) (*User, error) {
	var u User
	var en int
	var plan sql.NullInt64
	var lim sql.NullString
	if err := r.Scan(&u.ID, &u.Name, &u.Note, &en, &plan, &lim, &u.ExpiresAt, &u.SubToken, &u.PeriodStart, &u.PeriodUp, &u.PeriodDown,
		&u.TotalUp, &u.TotalDown, &u.LastSeen, &u.Status, &u.StatusReason, &u.RateDown, &u.RateUp, &u.Created); err != nil {
		return nil, err
	}
	u.Enabled = en == 1
	if plan.Valid {
		id := plan.Int64
		u.PlanID = &id
	}
	if lim.Valid && lim.String != "" && lim.String != "null" {
		u.Limits = &Limits{}
		fromJSON(lim.String, u.Limits)
	}
	return &u, nil
}

func (s *Store) Users() ([]*User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) User(id int64) (*User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) UserByName(name string) (*User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE name=? COLLATE NOCASE`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) UserByToken(tok string) (*User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE sub_token=?`, tok))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) SaveUser(u *User) error {
	var lim any
	if u.Limits != nil {
		lim = toJSON(u.Limits)
	}
	if u.Status == "" {
		u.Status = "ok"
	}
	if u.ID == 0 {
		if u.Created == 0 {
			u.Created = now()
		}
		if u.PeriodStart == 0 {
			u.PeriodStart = u.Created
		}
		res, err := s.db.Exec(`INSERT INTO users (name, note, enabled, plan_id, limits, expires_at, sub_token, period_start, period_up, period_down,
			total_up, total_down, last_seen, status, status_reason, rate_down, rate_up, created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			u.Name, u.Note, b2i(u.Enabled), u.PlanID, lim, u.ExpiresAt, u.SubToken, u.PeriodStart, u.PeriodUp, u.PeriodDown,
			u.TotalUp, u.TotalDown, u.LastSeen, u.Status, u.StatusReason, u.RateDown, u.RateUp, u.Created)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("Nutzername '%s' ist schon vergeben", u.Name)
			}
			return err
		}
		u.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := s.db.Exec(`UPDATE users SET name=?, note=?, enabled=?, plan_id=?, limits=?, expires_at=?, sub_token=?, period_start=?, period_up=?,
		period_down=?, total_up=?, total_down=?, last_seen=?, status=?, status_reason=?, rate_down=?, rate_up=? WHERE id=?`,
		u.Name, u.Note, b2i(u.Enabled), u.PlanID, lim, u.ExpiresAt, u.SubToken, u.PeriodStart, u.PeriodUp, u.PeriodDown,
		u.TotalUp, u.TotalDown, u.LastSeen, u.Status, u.StatusReason, u.RateDown, u.RateUp, u.ID)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("Nutzername '%s' ist schon vergeben", u.Name)
	}
	return err
}

func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

// ---------- Zugänge ----------

const peerCols = `id, user_id, server_id, name, kind, enabled, settings, secrets, total_up, total_down, last_rx, last_tx, handshake, last_seen, endpoint, created`

func scanPeer(r scanner) (*Peer, error) {
	var p Peer
	var en int
	var set, sec string
	if err := r.Scan(&p.ID, &p.UserID, &p.ServerID, &p.Name, &p.Kind, &en, &set, &sec, &p.TotalUp, &p.TotalDown,
		&p.LastRx, &p.LastTx, &p.Handshake, &p.LastSeen, &p.Endpoint, &p.Created); err != nil {
		return nil, err
	}
	p.Enabled = en == 1
	p.Settings, p.Secrets = M{}, M{}
	fromJSON(set, &p.Settings)
	fromJSON(sec, &p.Secrets)
	return &p, nil
}

func (s *Store) queryPeers(where string, args ...any) ([]*Peer, error) {
	rows, err := s.db.Query(`SELECT `+peerCols+` FROM peers `+where+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) Peers() ([]*Peer, error)                   { return s.queryPeers("") }
func (s *Store) PeersOfUser(id int64) ([]*Peer, error)     { return s.queryPeers("WHERE user_id=?", id) }
func (s *Store) PeersOfServer(id int64) ([]*Peer, error)   { return s.queryPeers("WHERE server_id=?", id) }

func (s *Store) Peer(id int64) (*Peer, error) {
	p, err := scanPeer(s.db.QueryRow(`SELECT `+peerCols+` FROM peers WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

func (s *Store) SavePeer(p *Peer) error {
	if p.Settings == nil {
		p.Settings = M{}
	}
	if p.Secrets == nil {
		p.Secrets = M{}
	}
	if p.ID == 0 {
		p.Created = now()
		res, err := s.db.Exec(`INSERT INTO peers (user_id, server_id, name, kind, enabled, settings, secrets, total_up, total_down, last_rx, last_tx,
			handshake, last_seen, endpoint, created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			p.UserID, p.ServerID, p.Name, p.Kind, b2i(p.Enabled), toJSON(p.Settings), toJSON(p.Secrets), p.TotalUp, p.TotalDown,
			p.LastRx, p.LastTx, p.Handshake, p.LastSeen, p.Endpoint, p.Created)
		if err != nil {
			return err
		}
		p.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := s.db.Exec(`UPDATE peers SET user_id=?, server_id=?, name=?, kind=?, enabled=?, settings=?, secrets=?, total_up=?, total_down=?,
		last_rx=?, last_tx=?, handshake=?, last_seen=?, endpoint=? WHERE id=?`,
		p.UserID, p.ServerID, p.Name, p.Kind, b2i(p.Enabled), toJSON(p.Settings), toJSON(p.Secrets), p.TotalUp, p.TotalDown,
		p.LastRx, p.LastTx, p.Handshake, p.LastSeen, p.Endpoint, p.ID)
	return err
}

func (s *Store) DeletePeer(id int64) error {
	_, err := s.db.Exec(`DELETE FROM peers WHERE id=?`, id)
	return err
}

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

// ExitTrafficSeries: [Zeitfenster, Ausgang, hoch, runter] ab since, zusammengefasst je bucket Sekunden.
func (s *Store) ExitTrafficSeries(since, bucket int64) ([][4]int64, error) {
	if bucket < 3600 {
		bucket = 3600
	}
	rows, err := s.db.Query(`SELECT (hour/?)*? AS b, exit_id, SUM(up), SUM(down) FROM exit_traffic WHERE hour >= ? GROUP BY b, exit_id ORDER BY b`,
		bucket, bucket, since-since%3600)
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

// ---------- Ereignisse ----------

func (s *Store) AddEvent(level, msg string) {
	_, _ = s.db.Exec(`INSERT INTO events (ts, level, msg) VALUES (?,?,?)`, now(), level, msg)
	_, _ = s.db.Exec(`DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - 5000`)
}

func (s *Store) Events(limit int, level string) ([]*Event, error) {
	q := `SELECT id, ts, level, msg FROM events`
	var args []any
	if level != "" {
		q += ` WHERE level=?`
		args = append(args, level)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.Level, &e.Msg); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// ---------- Admins & Sitzungen ----------

func (s *Store) Admins() ([]*Admin, error) {
	rows, err := s.db.Query(`SELECT id, username, pass_hash, totp_secret, totp_enabled, created FROM admins ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Admin
	for rows.Next() {
		var a Admin
		var te int
		if err := rows.Scan(&a.ID, &a.Username, &a.PassHash, &a.TOTPSecret, &te, &a.Created); err != nil {
			return nil, err
		}
		a.TOTPEnabled = te == 1
		out = append(out, &a)
	}
	return out, rows.Err()
}

func (s *Store) adminWhere(where string, arg any) (*Admin, error) {
	var a Admin
	var te int
	err := s.db.QueryRow(`SELECT id, username, pass_hash, totp_secret, totp_enabled, created FROM admins WHERE `+where, arg).
		Scan(&a.ID, &a.Username, &a.PassHash, &a.TOTPSecret, &te, &a.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	a.TOTPEnabled = te == 1
	return &a, err
}

func (s *Store) Admin(id int64) (*Admin, error)            { return s.adminWhere("id=?", id) }
func (s *Store) AdminByName(n string) (*Admin, error)      { return s.adminWhere("username=? COLLATE NOCASE", n) }

func (s *Store) SaveAdmin(a *Admin) error {
	if a.ID == 0 {
		a.Created = now()
		res, err := s.db.Exec(`INSERT INTO admins (username, pass_hash, totp_secret, totp_enabled, created) VALUES (?,?,?,?,?)`,
			a.Username, a.PassHash, a.TOTPSecret, b2i(a.TOTPEnabled), a.Created)
		if err != nil {
			return err
		}
		a.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := s.db.Exec(`UPDATE admins SET username=?, pass_hash=?, totp_secret=?, totp_enabled=? WHERE id=?`,
		a.Username, a.PassHash, a.TOTPSecret, b2i(a.TOTPEnabled), a.ID)
	return err
}

func (s *Store) DeleteAdmin(id int64) error {
	_, err := s.db.Exec(`DELETE FROM admins WHERE id=?`, id)
	return err
}

func (s *Store) CreateSession(se *Session) error {
	_, err := s.db.Exec(`INSERT INTO sessions (id, admin_id, created, expires, last_used, ip, agent) VALUES (?,?,?,?,?,?,?)`,
		se.ID, se.AdminID, se.Created, se.Expires, se.LastUsed, se.IP, se.Agent)
	return err
}

func (s *Store) Session(id string) (*Session, error) {
	var se Session
	err := s.db.QueryRow(`SELECT id, admin_id, created, expires, last_used, ip, agent FROM sessions WHERE id=?`, id).
		Scan(&se.ID, &se.AdminID, &se.Created, &se.Expires, &se.LastUsed, &se.IP, &se.Agent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &se, err
}

func (s *Store) TouchSession(id string, ts, expires int64) {
	_, _ = s.db.Exec(`UPDATE sessions SET last_used=?, expires=? WHERE id=?`, ts, expires, id)
}

func (s *Store) DeleteSession(id string) {
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE id=?`, id)
}

func (s *Store) DeleteSessionsOf(adminID int64, except string) {
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE admin_id=? AND id<>?`, adminID, except)
}

func (s *Store) SessionsOf(adminID int64) ([]*Session, error) {
	rows, err := s.db.Query(`SELECT id, admin_id, created, expires, last_used, ip, agent FROM sessions WHERE admin_id=? AND expires>? ORDER BY last_used DESC`, adminID, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		var se Session
		if err := rows.Scan(&se.ID, &se.AdminID, &se.Created, &se.Expires, &se.LastUsed, &se.IP, &se.Agent); err != nil {
			return nil, err
		}
		out = append(out, &se)
	}
	return out, rows.Err()
}

func (s *Store) PruneSessions() {
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE expires < ?`, now())
}
