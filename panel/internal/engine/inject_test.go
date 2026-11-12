package engine

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"vpnpanel/internal/proto"
	_ "vpnpanel/internal/proto/hysteria2"
	_ "vpnpanel/internal/proto/openvpn"
	_ "vpnpanel/internal/proto/proxy"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
)

// TestNoConfigInjection: Kein Eingabefeld eines Servers oder Zugangs darf eigene Zeilen in erzeugte
// Konfigurationsdateien, Firewall-Skripte oder Befehle schmuggeln (z. B. „PostUp = …“ in wg0.conf
// oder „script-security“ in einer OpenVPN-Datei). Jedes Feld wird mit präparierten Werten belegt;
// nimmt der Treiber den Wert an, darf die Markierung nirgends am Zeilenanfang oder als eigenes
// Befehlsargument auftauchen.
func TestNoConfigInjection(t *testing.T) {
	const mark = "INJ3CT"
	payloads := []string{
		"a\n" + mark + " = 1",
		"a\r" + mark + " = 1",
		"10.9.0.0/24\n" + mark + " = 1",
		"1.2.3.4\n" + mark,
		"a\"\n" + mark + ": x",
		"a'\n" + mark,
		"a " + mark,
		"a;" + mark,
		"a " + mark,
		"-" + mark,
	}
	for _, d := range proto.All() {
		info := d.Info()
		t.Run(info.ID, func(t *testing.T) {
			e, dry := newTest(t)
			sv := &store.Server{Name: "s", Protocol: info.ID, Enabled: true, Settings: store.M{}, State: store.M{}}
			if err := e.InitServer(sv); err != nil {
				t.Fatalf("Server: %v", err)
			}
			if err := e.St.SaveServer(sv); err != nil {
				t.Fatal(err)
			}
			u := &store.User{Name: "anna", Enabled: true, SubToken: proto.RandHex(16)}
			if err := e.St.SaveUser(u); err != nil {
				t.Fatal(err)
			}
			kinds := []string{""}
			for _, k := range info.Kinds {
				kinds = append(kinds, k.ID)
			}
			var peers []*store.Peer
			for i, kind := range kinds {
				s := store.M{}
				for _, k := range info.Kinds {
					if k.ID == kind {
						for key, v := range k.Defaults {
							s[key] = v
						}
					}
				}
				p := &store.Peer{UserID: u.ID, ServerID: sv.ID, Name: fmt.Sprintf("p%d", i), Kind: kind, Enabled: true, Settings: s}
				if err := e.InitPeer(sv, p); err != nil {
					continue
				}
				if err := e.St.SavePeer(p); err != nil {
					t.Fatal(err)
				}
				peers = append(peers, p)
			}
			if err := e.Apply(); err != nil {
				t.Logf("Apply (Grundzustand): %v", err)
			}

			keysOf := func(fields []proto.Field, have store.M) []string {
				set := map[string]bool{}
				for _, f := range fields {
					set[f.Key] = true
				}
				for k := range have {
					set[k] = true
				}
				out := make([]string, 0, len(set))
				for k := range set {
					out = append(out, k)
				}
				sort.Strings(out)
				return out
			}
			seen := map[string]bool{}
			check := func(what string) {
				t.Helper()
				_ = e.Apply()
				if _, err := e.SubLinksFor(u.ID, ""); err != nil {
					t.Logf("%s: Abo: %v", what, err)
				}
				for _, p := range peers {
					if cc, err := e.ClientConfig(p.ID); err == nil && cc != nil {
						for _, f := range cc.Files {
							scanInject(t, what+" → Client-Datei "+f.Name, f.Content, mark)
						}
					}
				}
				_ = filepath.WalkDir(dry.Root, func(path string, de fs.DirEntry, err error) error {
					if err != nil || de.IsDir() {
						return nil
					}
					b, _ := os.ReadFile(path)
					scanInject(t, what+" → "+strings.TrimPrefix(filepath.ToSlash(path), filepath.ToSlash(dry.Root)), string(b), mark)
					return nil
				})
				for _, in := range dry.Stdin {
					scanInject(t, what+" → stdin", in, mark)
				}
				for _, l := range dry.Log() {
					if seen[l] {
						continue
					}
					seen[l] = true
					// eigenes Befehlsargument (Leerzeichen davor) wäre ein eingeschleuster Schalter
					if strings.Contains(l, " "+mark) || strings.Contains(l, " -"+mark) {
						t.Errorf("%s: Markierung als Befehlsargument: %s", what, l)
					}
				}
				dry.Stdin = nil
			}

			for _, key := range keysOf(info.ServerFields, sv.Settings) {
				orig, had := sv.Settings[key]
				for _, pl := range payloads {
					sv.Settings[key] = pl
					if err := e.InitServer(sv); err == nil {
						if err := e.St.SaveServer(sv); err != nil {
							t.Fatal(err)
						}
						check(fmt.Sprintf("Server-Feld %q = %q", key, pl))
					}
					if had {
						sv.Settings[key] = orig
					} else {
						delete(sv.Settings, key)
					}
				}
				if err := e.InitServer(sv); err != nil {
					t.Fatalf("Server-Feld %q zurücksetzen: %v", key, err)
				}
				_ = e.St.SaveServer(sv)
			}
			for _, p := range peers {
				for _, key := range keysOf(info.PeerFields, p.Settings) {
					orig, had := p.Settings[key]
					for _, pl := range payloads {
						p.Settings[key] = pl
						if err := e.InitPeer(sv, p); err == nil {
							if err := e.St.SavePeer(p); err != nil {
								t.Fatal(err)
							}
							check(fmt.Sprintf("Zugang (%s) Feld %q = %q", p.Kind, key, pl))
						}
						if had {
							p.Settings[key] = orig
						} else {
							delete(p.Settings, key)
						}
					}
					if err := e.InitPeer(sv, p); err != nil {
						t.Fatalf("Zugang Feld %q zurücksetzen: %v", key, err)
					}
					_ = e.St.SavePeer(p)
				}
			}
		})
	}
}

// scanInject: Markierung am Zeilenanfang (nach optionalen Leerzeichen) = eigene Zeile eingeschleust.
func scanInject(t *testing.T, where, text, mark string) {
	t.Helper()
	if !strings.Contains(text, mark) {
		return
	}
	for _, l := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if strings.HasPrefix(strings.TrimLeft(l, " \t"), mark) {
			t.Errorf("%s: eingeschleuste Zeile %q", where, l)
		}
	}
}

var _ = system.Real{}
