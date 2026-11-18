//go:build lab && linux

package exits

// Labortest (root, Netzwerk-Namensräume): weicher Wechsel und Verteilung je Ziel mit der echten
// Tabelle aus pinScript. Aufbau: Gerät c → Server r → zwei Ausgänge (ex1/ex2, je ein Namensraum mit
// NAT als „Anbieter“) → Ziel t. Das Ziel meldet die Absenderadresse – daran ist der Ausgang zu sehen.
//
//	go test -c -tags lab -o /tmp/exitslab ./internal/exits && sudo /tmp/exitslab -test.v -test.run Lab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const labSetup = `set -e
for n in vxr vxu1 vxu2 vxt vxc; do ip netns del $n 2>/dev/null || true; done
for n in vxr vxu1 vxu2 vxt vxc; do ip netns add $n; ip -n $n link set lo up; done
X() { ip netns exec "$@"; }
ip link add ex1 netns vxr type veth peer name upl netns vxu1
ip link add ex2 netns vxr type veth peer name upl netns vxu2
ip link add cl netns vxr type veth peer name eth0 netns vxc
ip link add dn netns vxu1 type veth peer name ta netns vxt
ip link add dn netns vxu2 type veth peer name tb netns vxt
X vxr ip a add 10.1.0.1/30 dev ex1; X vxr ip a add 10.2.0.1/30 dev ex2; X vxr ip a add 10.9.0.1/24 dev cl
X vxu1 ip a add 10.1.0.2/30 dev upl; X vxu1 ip a add 10.5.1.1/30 dev dn
X vxu2 ip a add 10.2.0.2/30 dev upl; X vxu2 ip a add 10.5.2.1/30 dev dn
X vxt ip a add 10.5.1.2/30 dev ta; X vxt ip a add 10.5.2.2/30 dev tb
for i in $(seq 10 25); do X vxt ip a add 192.0.2.$i/32 dev lo; done
X vxc ip a add 10.9.0.2/24 dev eth0
for p in "vxr ex1" "vxr ex2" "vxr cl" "vxu1 upl" "vxu1 dn" "vxu2 upl" "vxu2 dn" "vxt ta" "vxt tb" "vxc eth0"; do set -- $p; X $1 ip link set $2 up; done
X vxc ip r add default via 10.9.0.1
X vxu1 ip r add default via 10.5.1.2; X vxu2 ip r add default via 10.5.2.2
for u in vxu1 vxu2; do X $u sysctl -qw net.ipv4.ip_forward=1; X $u nft add table ip n; X $u nft 'add chain ip n p { type nat hook postrouting priority 100; }'; X $u nft add rule ip n p oifname dn masquerade; done
X vxr sysctl -qw net.ipv4.ip_forward=1
for i in all ex1 ex2; do X vxr sysctl -qw net.ipv4.conf.$i.rp_filter=0; done
X vxr ip r add blackhole default
X vxr ip r add default via 10.1.0.2 dev ex1 table 2001; X vxr ip r add blackhole default metric 10000 table 2001
X vxr ip r add default via 10.2.0.2 dev ex2 table 2002; X vxr ip r add blackhole default metric 10000 table 2002
X vxr ip r add default via 10.1.0.2 dev ex1 table 3001; X vxr ip r add blackhole default metric 10000 table 3001
X vxr ip rule add priority 6001 fwmark 0x01000000/0x7f000000 lookup 3001
X vxr ip rule add priority 6101 fwmark 0x41000000/0x7f000000 lookup 2001
X vxr ip rule add priority 6102 fwmark 0x42000000/0x7f000000 lookup 2002
printf 'table ip nat {\n chain post {\n  type nat hook postrouting priority 100;\n  oifname { "ex1", "ex2" } masquerade\n }\n}\ntable inet vpnpanel {\n chain vp_pre {\n  type filter hook prerouting priority mangle;\n  ip saddr 10.9.0.2 ip daddr != 10.9.0.0/24 meta mark set 0x01000000\n }\n}\n' | X vxr nft -f -
X vxr nft -f "$D/pin.nft"
ip netns exec vxt python3 "$D/srv.py" >/dev/null 2>&1 </dev/null & SRV=$!
trap 'kill $SRV 2>/dev/null; ip netns pids vxt 2>/dev/null | xargs -r kill 2>/dev/null; for n in vxr vxu1 vxu2 vxt vxc; do ip netns del $n 2>/dev/null; done' EXIT
sleep 1.5
`

const labSoft = `
run() { # $1 = Namensraum, $2 = Markierung
  echo 0 > "$D/ready"
  X $1 python3 "$D/cli.py" $2 "$D/ready" & P=$!
  i=0; while [ "$(cat "$D/ready")" != "1" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
  X vxr nft -f "$D/switch.nft"                                  # Panel: neue Verbindungen → ex2 …
  X vxr ip r replace default via 10.2.0.2 dev ex2 table 3001    # … dann die Gruppen-Route
  echo go > "$D/ready"; wait $P
  X vxr nft -f "$D/pin.nft"; X vxr ip r replace default via 10.1.0.2 dev ex1 table 3001
}
echo "== weitergeleitet"; run vxc 0
echo "== lokal"; run vxr 0x01000000
`

const labDest = `
X vxr nft -f "$D/dest.nft"
X vxc python3 "$D/dest.py"
echo "ct ex1=$(X vxr conntrack -L -m 0x41000000/0x7f000000 2>/dev/null | grep -c src=) ex3=$(X vxr conntrack -L -m 0x43000000/0x7f000000 2>/dev/null | grep -c src=)"
`

const pySrv = `import socket,threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",9000)); s.listen(50)
def h(c,a):
    c.sendall(("src=%s\n"%a[0]).encode())
    while True:
        d=c.recv(100)
        if not d: break
        c.sendall(d)
while True:
    c,a=s.accept(); threading.Thread(target=h,args=(c,a),daemon=True).start()
`

const pyCli = `import socket,sys,time
mark=int(sys.argv[1],0); rf=sys.argv[2]
def conn():
    s=socket.socket()
    if mark: s.setsockopt(socket.SOL_SOCKET,36,mark)
    s.settimeout(4); s.connect(("192.0.2.10",9000)); return s, s.recv(100).decode().strip()
a,src=conn(); print("lang:",src)
open(rf,"w").write("1")
t=time.time()
while open(rf).read().strip()!="go" and time.time()-t<15: time.sleep(0.1)
try:
    a.sendall(b"ping"); print("lang nach Wechsel:", a.recv(100).decode())
except Exception as e: print("lang nach Wechsel: FEHLER", e)
b,src=conn(); print("neu:",src)
`

const pyDest = `import socket
res={}
for rnd in range(2):
    for i in range(10,26):
        s=socket.socket(); s.settimeout(4); s.connect(("192.0.2.%d"%i,9000)); src=s.recv(50).decode().strip(); s.close()
        res.setdefault(i,set()).add(src)
via={}
for v in res.values():
    for x in v: via[x]=via.get(x,0)+1
print("je Ausgang", sorted(via.items()), "stabil", all(len(v)==1 for v in res.values()))
`

func labRun(t *testing.T, body string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("nur als root")
	}
	for _, bin := range []string{"ip", "nft", "python3", "conntrack"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " fehlt")
		}
	}
	d := t.TempDir()
	files := map[string]string{
		"pin.nft":    pinScript([]int{1, 2}, []pinGroup{{Slot: 1, Exits: []int{1}}}),
		"switch.nft": pinScript([]int{1, 2}, []pinGroup{{Slot: 1, Exits: []int{2}}}),
		"dest.nft":   pinScript([]int{1, 2, 3}, []pinGroup{{Slot: 1, Exits: []int{1, 2}, Seed: 0x1234}}),
		"srv.py":     pySrv, "cli.py": pyCli, "dest.py": pyDest,
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", "-c", labSetup+body)
	cmd.Env = append(os.Environ(), "D="+d)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("Labor: %v", err)
	}
	return string(out)
}

// Laufende Verbindungen bleiben nach dem Wechsel auf ex1, neue gehen über ex2 – weitergeleitet
// (Geräte) und lokal mit Gruppen-Markierung (Proxy, Xray, DNS).
func TestLabSoftSwitch(t *testing.T) {
	out := labRun(t, labSoft)
	for _, part := range strings.Split(out, "== ")[1:] {
		if !strings.Contains(part, "lang: src=10.5.1.1") || !strings.Contains(part, "lang nach Wechsel: ping") || !strings.Contains(part, "neu: src=10.5.2.1") {
			t.Fatalf("weicher Wechsel fehlgeschlagen:\n%s", part)
		}
	}
	if strings.Count(out, "== ") != 2 {
		t.Fatal("nicht alle Fälle gelaufen")
	}
}

// Je Ziel: beide Ausgänge werden genutzt, ein Ziel bleibt beim selben Ausgang; conntrack zählt je Ausgang.
func TestLabDest(t *testing.T) {
	out := labRun(t, labDest)
	if !strings.Contains(out, "'src=10.5.1.1', 8") || !strings.Contains(out, "'src=10.5.2.1', 8") || !strings.Contains(out, "stabil True") {
		t.Fatalf("Verteilung je Ziel fehlgeschlagen:\n%s", out)
	}
	if !strings.Contains(out, " ex3=0") || strings.Contains(out, "ct ex1=0 ") {
		t.Fatalf("conntrack-Zählung je Ausgang falsch:\n%s", out)
	}
}
