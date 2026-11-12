package engine

import (
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func answerTTL(t *testing.T, ttl uint32) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true})
	_ = b.StartQuestions()
	n := dnsmessage.MustNewName("example.com.")
	_ = b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.AResource(dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}})
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Zwischenspeicher: Mindest-/Höchstdauer und „aus“.
func TestDNSCacheOptions(t *testing.T) {
	g := &dnsGate{cacheMax: 100, ttlMin: 300, ttlMax: 3600}
	g.store("a", answerTTL(t, 10))
	if left := time.Until(g.answers["a"].exp); left < 290*time.Second || left > 301*time.Second {
		t.Errorf("Mindestdauer nicht angewandt: %v", left)
	}
	g.store("b", answerTTL(t, 90000))
	if left := time.Until(g.answers["b"].exp); left > 3601*time.Second {
		t.Errorf("Höchstdauer nicht angewandt: %v", left)
	}
	off := &dnsGate{cacheMax: 0}
	off.store("a", answerTTL(t, 600))
	if len(off.answers) != 0 {
		t.Errorf("Zwischenspeicher aus, trotzdem gespeichert")
	}
	// volle Liste: ältere fallen heraus, neue Antwort ist drin
	small := &dnsGate{cacheMax: 5, ttlMax: 3600}
	for _, k := range []string{"1", "2", "3", "4", "5", "6", "7"} {
		small.store(k, answerTTL(t, 600))
	}
	if len(small.answers) > 5 || small.answers["7"] == nil {
		t.Errorf("Größe nicht eingehalten: %d", len(small.answers))
	}
}
