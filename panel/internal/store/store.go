package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	// DNS-Protokoll: welcher DNS-Server (bzw. Unbound) geantwortet hat
	`ALTER TABLE dns_log ADD COLUMN upstream TEXT NOT NULL DEFAULT '';`,
	// DNS-Protokoll: Weg von Anfragen ohne VPN (dns = Port 53, doh, dot; „-addr“ = ohne Kennung)
	`ALTER TABLE dns_log ADD COLUMN transport TEXT NOT NULL DEFAULT '';`,
	// Konto: E-Mail und Benachrichtigungen je Administrator, Anmeldeprotokoll
	`ALTER TABLE admins ADD COLUMN email TEXT NOT NULL DEFAULT '';
	 ALTER TABLE admins ADD COLUMN notify INTEGER NOT NULL DEFAULT 0;
	 CREATE TABLE login_log (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, username TEXT NOT NULL DEFAULT '', admin_id INTEGER NOT NULL DEFAULT 0,
	   ip TEXT NOT NULL DEFAULT '', agent TEXT NOT NULL DEFAULT '', ok INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '');
	 CREATE INDEX login_log_ts ON login_log(ts);`,
	// Login-Sperre nach Adresse (IPv4 einzeln, IPv6 je /64); until 0 = dauerhaft
	`CREATE TABLE login_locks (net TEXT PRIMARY KEY, until INTEGER NOT NULL DEFAULT 0, manual INTEGER NOT NULL DEFAULT 0,
	   strikes INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL);`,
	// Verkehr über die Ausgangsgruppen je Stunde (dem jeweils aktiven Ausgang zugerechnet)
	`CREATE TABLE group_traffic (group_id INTEGER NOT NULL, hour INTEGER NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
	   PRIMARY KEY (group_id, hour));
	 CREATE INDEX group_traffic_hour ON group_traffic(hour);`,
	// Block-Prüfung: Ergebnis je Ziel und Ausgang (siehe blockcheck.go)
	`CREATE TABLE block_results (domain TEXT NOT NULL, exit_id INTEGER NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
	   checked INTEGER NOT NULL DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, since INTEGER NOT NULL DEFAULT 0, seen INTEGER NOT NULL DEFAULT 0,
	   PRIMARY KEY (domain, exit_id));
	 CREATE INDEX dns_log_via ON dns_log(via, ts);`,
	// SmartDNS-Verkehr je Stunde: kind 0 = VPN-Geräte (Teil von traffic), 1 = Geräte ohne VPN über den Proxy
	`CREATE TABLE smart_traffic (hour INTEGER NOT NULL, kind INTEGER NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
	   PRIMARY KEY (hour, kind));`,
}

// SchemaVersion: Stand der Datenbank, den dieses Programm kennt (für die Prüfung von Sicherungen).
func SchemaVersion() int { return len(migrations) }

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
