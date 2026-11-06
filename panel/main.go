// vpnpanel – Webinterface und Verwaltung für WireGuard + VLESS/Reality (und weitere Protokolle).
//
//	vpnpanel serve            Dienst (Weboberfläche, Abo, Statistik)
//	vpnpanel <befehl>         Kommandozeile, auch als „vpn <befehl>“ (Symlink)
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"vpnpanel/internal/api"
	"vpnpanel/internal/engine"
	_ "vpnpanel/internal/proto/vless"
	_ "vpnpanel/internal/proto/wireguard"
	"vpnpanel/internal/store"
	"vpnpanel/internal/system"
	"vpnpanel/internal/webui"
)

var version = "1.0.0"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type opts struct {
	db, dataDir, listen, direct, cert, key, legacy string
	proxy, dev, demo                       bool
}

func parseOpts(args []string) (*opts, []string) {
	fs := flag.NewFlagSet("vpnpanel", flag.ExitOnError)
	o := &opts{}
	fs.StringVar(&o.dataDir, "data", env("VPNPANEL_DATA", "/etc/vpn"), "Datenverzeichnis")
	fs.StringVar(&o.db, "db", env("VPNPANEL_DB", ""), "Datenbank (Standard: <data>/panel.db)")
	fs.StringVar(&o.listen, "listen", env("VPNPANEL_LISTEN", "127.0.0.1:8480"), "Adresse des Webservers")
	fs.StringVar(&o.direct, "direct", env("VPNPANEL_DIRECT", ""), "zusätzlicher direkter Zugang ohne nginx, z. B. 0.0.0.0:9443 (leer = aus)")
	fs.StringVar(&o.cert, "tls-cert", env("VPNPANEL_CERT", ""), "TLS-Zertifikat (z. B. Cloudflare-Origin)")
	fs.StringVar(&o.key, "tls-key", env("VPNPANEL_KEY", ""), "TLS-Schlüssel")
	fs.BoolVar(&o.proxy, "proxy-protocol", env("VPNPANEL_PROXY", "1") == "1", "PROXY-Protocol von nginx erwarten")
	fs.BoolVar(&o.dev, "dev", false, "Testmodus: keine Systembefehle, Dateien unter <data>/dryroot")
	fs.BoolVar(&o.demo, "demo", false, "Demo-Daten anlegen (nur mit -dev)")
	fs.StringVar(&o.legacy, "legacy", env("VPNPANEL_LEGACY", "/etc/vpn"), "Verzeichnis des bisherigen Setups (Übernahme)")
	_ = fs.Parse(args)
	if o.db == "" {
		o.db = filepath.Join(o.dataDir, "panel.db")
	}
	return o, fs.Args()
}

func open(o *opts) (*engine.Engine, error) {
	if err := os.MkdirAll(o.dataDir, 0o700); err != nil {
		return nil, err
	}
	st, err := store.Open(o.db)
	if err != nil {
		return nil, err
	}
	var sys system.Runner = system.Real{}
	lock := "/run/vpnpanel.lock"
	if o.dev {
		sys = &system.Dry{Root: filepath.Join(o.dataDir, "dryroot")}
		lock = ""
	}
	return engine.New(st, sys, engine.Config{PanelBackend: o.listen, DataDir: o.dataDir, LockPath: lock}), nil
}

func main() {
	log.SetFlags(log.LstdFlags)
	args := os.Args[1:]
	// Als „vpn“ aufgerufen → Kommandozeile
	if filepath.Base(os.Args[0]) == "vpn" {
		cli(args)
		return
	}
	if len(args) > 0 && args[0] == "serve" {
		serve(args[1:])
		return
	}
	cli(args)
}

func serve(args []string) {
	o, _ := parseOpts(args)
	e, err := open(o)
	if err != nil {
		log.Fatal(err)
	}
	defer e.St.Close()

	if !o.dev {
		if ok, err := e.ImportLegacy(o.legacy); err != nil {
			log.Fatalf("Übernahme des bisherigen Setups: %v", err)
		} else if ok {
			log.Printf("Bisheriges Setup übernommen")
		}
	}
	if o.demo && o.dev {
		if err := seedDemo(e); err != nil {
			log.Printf("Demo-Daten: %v", err)
		}
	}
	ensureAdmin(e, o)

	if err := e.Apply(); err != nil {
		log.Printf("Anwenden beim Start: %v", err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { e.Run(stop); close(done) }()

	secure := o.cert != "" || !o.dev
	a := api.New(e, webui.FS(), secure, version)
	srv := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}

	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		log.Fatal(err)
	}
	if o.proxy && !o.dev {
		ln = &proxyproto.Listener{Listener: ln, ReadHeaderTimeout: 5 * time.Second}
	}
	go func() {
		var err error
		if o.cert != "" {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			log.Printf("Panel auf https://%s", o.listen)
			err = srv.ServeTLS(ln, o.cert, o.key)
		} else {
			log.Printf("Panel auf http://%s", o.listen)
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	// Direkter Zugang (IP:Port) ohne nginx und ohne PROXY-Protocol. Hier kommt nichts über
	// Cloudflare, also darf CF-Connecting-IP nicht geglaubt werden (sonst umgehbare Login-Sperre).
	var dsrv *http.Server
	if o.direct != "" {
		h := a.Handler()
		dsrv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Del("CF-Connecting-IP")
			h.ServeHTTP(w, r)
		}), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
		dln, err := net.Listen("tcp", o.direct)
		if err != nil {
			log.Fatalf("Direkter Zugang %s: %v", o.direct, err)
		}
		go func() {
			var err error
			if o.cert != "" {
				dsrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
				log.Printf("Direkter Zugang auf https://%s", o.direct)
				err = dsrv.ServeTLS(dln, o.cert, o.key)
			} else {
				log.Printf("Direkter Zugang auf http://%s (ohne TLS!)", o.direct)
				err = dsrv.Serve(dln)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatal(err)
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("Beende …")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	if dsrv != nil {
		_ = dsrv.Shutdown(ctx)
	}
	close(stop)
	<-done
}

// ensureAdmin legt beim ersten Start einen Administrator mit Zufallspasswort an.
func ensureAdmin(e *engine.Engine, o *opts) {
	admins, err := e.St.Admins()
	if err != nil || len(admins) > 0 {
		return
	}
	pw := api.RandomPassword()
	h, _ := api.HashPassword(pw)
	if err := e.St.SaveAdmin(&store.Admin{Username: "admin", PassHash: h}); err != nil {
		log.Printf("Administrator anlegen: %v", err)
		return
	}
	f := filepath.Join(o.dataDir, "panel-admin.txt")
	_ = os.WriteFile(f, []byte("Benutzer: admin\nPasswort: "+pw+"\n"), 0o600)
	log.Printf("Erster Administrator „admin“ angelegt, Passwort steht in %s (nach dem Anmelden ändern und 2FA einrichten)", f)
	e.Log("info", "Erster Administrator „admin“ angelegt")
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "Fehler: "+format+"\n", a...)
	os.Exit(1)
}

func trimArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.TrimSpace(a) != "" {
			out = append(out, a)
		}
	}
	return out
}
