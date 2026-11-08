package store

import (
	"database/sql"
	"errors"
)

// Object: Ausgang („exit“), Ausgangsgruppe („group“) oder IP-Liste („iplist“).
// Data ist frei (vom jeweiligen Paket typisiert), Secrets geht nie an die Oberfläche.
type Object struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Data    M      `json:"data"`
	Secrets M      `json:"-"`
	Created int64  `json:"created"`
}

const objCols = `id, kind, name, enabled, data, secrets, created`

func scanObject(r scanner) (*Object, error) {
	var o Object
	var en int
	var d, sec string
	if err := r.Scan(&o.ID, &o.Kind, &o.Name, &en, &d, &sec, &o.Created); err != nil {
		return nil, err
	}
	o.Enabled = en == 1
	o.Data, o.Secrets = M{}, M{}
	fromJSON(d, &o.Data)
	fromJSON(sec, &o.Secrets)
	return &o, nil
}

func (s *Store) Objects(kind string) ([]*Object, error) {
	rows, err := s.db.Query(`SELECT `+objCols+` FROM objects WHERE kind=? ORDER BY id`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Object
	for rows.Next() {
		o, err := scanObject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) Object(kind string, id int64) (*Object, error) {
	o, err := scanObject(s.db.QueryRow(`SELECT `+objCols+` FROM objects WHERE kind=? AND id=?`, kind, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return o, err
}

func (s *Store) SaveObject(o *Object) error {
	if o.Data == nil {
		o.Data = M{}
	}
	if o.Secrets == nil {
		o.Secrets = M{}
	}
	if o.ID == 0 {
		o.Created = now()
		res, err := s.db.Exec(`INSERT INTO objects (kind, name, enabled, data, secrets, created) VALUES (?,?,?,?,?,?)`,
			o.Kind, o.Name, b2i(o.Enabled), toJSON(o.Data), toJSON(o.Secrets), o.Created)
		if err != nil {
			return err
		}
		o.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := s.db.Exec(`UPDATE objects SET name=?, enabled=?, data=?, secrets=? WHERE kind=? AND id=?`,
		o.Name, b2i(o.Enabled), toJSON(o.Data), toJSON(o.Secrets), o.Kind, o.ID)
	return err
}

func (s *Store) DeleteObject(kind string, id int64) error {
	_, err := s.db.Exec(`DELETE FROM objects WHERE kind=? AND id=?`, kind, id)
	return err
}
