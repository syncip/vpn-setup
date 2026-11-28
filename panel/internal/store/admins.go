package store

// Ereignisse, Administratoren und Sitzungen, Anmeldeprotokoll, Sicherung.

import (
	"database/sql"
	"errors"
	"fmt"
)

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
	rows, err := s.db.Query(`SELECT id, username, pass_hash, totp_secret, totp_enabled, email, notify, created FROM admins ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Admin
	for rows.Next() {
		var a Admin
		var te, nt int
		if err := rows.Scan(&a.ID, &a.Username, &a.PassHash, &a.TOTPSecret, &te, &a.Email, &nt, &a.Created); err != nil {
			return nil, err
		}
		a.TOTPEnabled, a.Notify = te == 1, nt == 1
		out = append(out, &a)
	}
	return out, rows.Err()
}

func (s *Store) adminWhere(where string, arg any) (*Admin, error) {
	var a Admin
	var te, nt int
	err := s.db.QueryRow(`SELECT id, username, pass_hash, totp_secret, totp_enabled, email, notify, created FROM admins WHERE `+where, arg).
		Scan(&a.ID, &a.Username, &a.PassHash, &a.TOTPSecret, &te, &a.Email, &nt, &a.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	a.TOTPEnabled, a.Notify = te == 1, nt == 1
	return &a, err
}

func (s *Store) Admin(id int64) (*Admin, error) { return s.adminWhere("id=?", id) }
func (s *Store) AdminByName(n string) (*Admin, error) {
	return s.adminWhere("username=? COLLATE NOCASE", n)
}

func (s *Store) SaveAdmin(a *Admin) error {
	if a.ID == 0 {
		a.Created = now()
		res, err := s.db.Exec(`INSERT INTO admins (username, pass_hash, totp_secret, totp_enabled, email, notify, created) VALUES (?,?,?,?,?,?,?)`,
			a.Username, a.PassHash, a.TOTPSecret, b2i(a.TOTPEnabled), a.Email, b2i(a.Notify), a.Created)
		if err != nil {
			return err
		}
		a.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := s.db.Exec(`UPDATE admins SET username=?, pass_hash=?, totp_secret=?, totp_enabled=?, email=?, notify=? WHERE id=?`,
		a.Username, a.PassHash, a.TOTPSecret, b2i(a.TOTPEnabled), a.Email, b2i(a.Notify), a.ID)
	return err
}

func (s *Store) DeleteAdmin(id int64) error {
	_, err := s.db.Exec(`DELETE FROM admins WHERE id=?`, id)
	if err == nil {
		// Fenster-Anordnung des Admins mit entfernen (api/layout.go)
		_, _ = s.db.Exec(`DELETE FROM settings WHERE key=?`, fmt.Sprintf("state:layout:%d", id))
	}
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

// ---------- Anmeldeprotokoll ----------

// AddLogin vermerkt einen Anmeldeversuch; behalten werden höchstens 90 Tage bzw. 5000 Einträge.
func (s *Store) AddLogin(l *LoginEntry) {
	if l.TS == 0 {
		l.TS = now()
	}
	_, _ = s.db.Exec(`INSERT INTO login_log (ts, username, admin_id, ip, agent, ok, reason) VALUES (?,?,?,?,?,?,?)`,
		l.TS, l.Username, l.AdminID, l.IP, l.Agent, b2i(l.OK), l.Reason)
	_, _ = s.db.Exec(`DELETE FROM login_log WHERE ts < ? OR id <= (SELECT MAX(id) FROM login_log) - 5000`, now()-90*86400)
}

// Logins: die letzten Anmeldeversuche (neueste zuerst).
func (s *Store) Logins(limit int) ([]*LoginEntry, error) {
	rows, err := s.db.Query(`SELECT id, ts, username, admin_id, ip, agent, ok, reason FROM login_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*LoginEntry
	for rows.Next() {
		var l LoginEntry
		var ok int
		if err := rows.Scan(&l.ID, &l.TS, &l.Username, &l.AdminID, &l.IP, &l.Agent, &ok, &l.Reason); err != nil {
			return nil, err
		}
		l.OK = ok == 1
		out = append(out, &l)
	}
	return out, rows.Err()
}

// LoginCounts: erfolgreiche und fehlgeschlagene Anmeldungen seit since.
func (s *Store) LoginCounts(since int64) (ok, failed int64, err error) {
	err = s.db.QueryRow(`SELECT COALESCE(SUM(ok=1),0), COALESCE(SUM(ok=0),0) FROM login_log WHERE ts >= ?`, since).Scan(&ok, &failed)
	return
}

// ---------- Sicherung ----------

// Snapshot schreibt eine konsistente Kopie der Datenbank nach path (VACUUM INTO, auch bei laufendem
// Betrieb). Ohne Protokolle fallen DNS-Protokoll und Anmeldeprotokoll weg.
func (s *Store) Snapshot(path string, withLogs bool) error {
	if _, err := s.db.Exec(`VACUUM INTO ?`, path); err != nil {
		return err
	}
	if withLogs {
		return nil
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return err
	}
	defer db.Close()
	for _, q := range []string{`DELETE FROM dns_log`, `DELETE FROM login_log`, `DELETE FROM login_locks WHERE manual=0`, `VACUUM`} {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// CheckBackupDB prüft eine Datenbank aus einer Sicherung: lesbar, nicht neuer als dieses Programm,
// mit mindestens einem Administrator.
func CheckBackupDB(path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var v int
	if err := db.QueryRow(`SELECT COALESCE(MAX(v),0) FROM schema_version`).Scan(&v); err != nil {
		return fmt.Errorf("keine Panel-Datenbank: %w", err)
	}
	if v > len(migrations) {
		return fmt.Errorf("die Sicherung stammt von einer neueren Panel-Version (Datenbank-Stand %d, dieses Programm kennt %d) – erst das Panel aktualisieren", v, len(migrations))
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM admins`).Scan(&n); err != nil {
		return fmt.Errorf("Datenbank unvollständig: %w", err)
	}
	if n == 0 {
		return errors.New("die Sicherung enthält keinen Administrator")
	}
	var res string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&res); err != nil || res != "ok" {
		return fmt.Errorf("Datenbank beschädigt: %s %v", res, err)
	}
	return nil
}

// SnapshotFile kopiert eine Datenbank-Datei konsistent nach dst, ohne sie zu migrieren
// (für den Wiederherstellungspunkt vor dem Start einer neuen Version). Liefert ihren Stand.
func SnapshotFile(path, dst string) (schema int, err error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	if err := db.QueryRow(`SELECT COALESCE(MAX(v),0) FROM schema_version`).Scan(&schema); err != nil {
		return 0, fmt.Errorf("keine Panel-Datenbank: %w", err)
	}
	if dst == "" { // nur den Stand abfragen
		return schema, nil
	}
	if _, err := db.Exec(`VACUUM INTO ?`, dst); err != nil {
		return 0, err
	}
	return schema, nil
}
