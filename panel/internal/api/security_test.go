package api

import "testing"

func TestFromCloudflare(t *testing.T) {
	for ip, want := range map[string]bool{
		"104.16.1.1": true, "2606:4700::1": true, "::ffff:172.64.0.5": true,
		"1.2.3.4": false, "127.0.0.1": false, "2001:db8::1": false, "kaputt": false,
	} {
		if got := fromCloudflare(ip); got != want {
			t.Errorf("%s: %v, erwartet %v", ip, got, want)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter()
	for i := 0; i < 8; i++ {
		if !l.allow("u:admin") {
			t.Fatalf("Versuch %d gesperrt", i+1)
		}
		l.fail("u:admin")
	}
	if l.allow("u:admin") {
		t.Errorf("nach 8 Fehlversuchen nicht gesperrt")
	}
	if !l.allow("u:other") {
		t.Errorf("anderer Name gesperrt")
	}
	l.reset("u:admin")
	if !l.allow("u:admin") {
		t.Errorf("nach reset gesperrt")
	}
}

func TestUsedCodes(t *testing.T) {
	var u usedCodes
	if !u.take("1:123456") || u.take("1:123456") {
		t.Errorf("TOTP-Code lässt sich zweimal benutzen")
	}
	if !u.take("2:123456") {
		t.Errorf("gleicher Code eines anderen Admins abgelehnt")
	}
}

func TestBadLabel(t *testing.T) {
	for n, bad := range map[string]bool{
		"Handy Martin": false, "Büro-PC (alt)": false, "": true,
		"a\nPostUp = x": true, "a\rb": true, "a\x00": true, "a b": true,
		"012345678901234567890123456789012345678901234567890": true,
	} {
		if badLabel(n) != bad {
			t.Errorf("%q: erwartet %v", n, bad)
		}
	}
}
