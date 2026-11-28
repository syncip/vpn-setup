package store

// Server, Tarife, Nutzer und Zugänge.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

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

func (s *Store) Peers() ([]*Peer, error)               { return s.queryPeers("") }
func (s *Store) PeersOfUser(id int64) ([]*Peer, error) { return s.queryPeers("WHERE user_id=?", id) }
func (s *Store) PeersOfServer(id int64) ([]*Peer, error) {
	return s.queryPeers("WHERE server_id=?", id)
}

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
