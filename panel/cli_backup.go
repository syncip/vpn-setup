package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"vpnpanel/internal/backup"
	"vpnpanel/internal/engine"
	"vpnpanel/internal/store"
)

// askPassword: Passwort aus der Umgebung oder vom Terminal (ohne Echo, wenn stty da ist).
func askPassword(prompt string) string {
	if pw := os.Getenv("VPNPANEL_BACKUP_PASSWORD"); pw != "" {
		return pw
	}
	fmt.Fprint(os.Stderr, prompt)
	echoOff := exec.Command("stty", "-echo")
	echoOff.Stdin = os.Stdin
	hidden := echoOff.Run() == nil
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if hidden {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		_ = on.Run()
		fmt.Fprintln(os.Stderr)
	}
	return strings.TrimRight(line, "\r\n")
}

func cmdBackup(e *engine.Engine, o *opts, args []string) {
	if len(args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}
	file := args[1]
	switch args[0] {
	case "create":
		logs := true
		for _, a := range args[2:] {
			if a == "--ohne-protokolle" || a == "--no-logs" {
				logs = false
			}
		}
		pw := askPassword("Passwort für die Sicherung (mind. 12 Zeichen): ")
		if os.Getenv("VPNPANEL_BACKUP_PASSWORD") == "" && askPassword("Wiederholen: ") != pw {
			fatal("die Passwörter stimmen nicht überein")
		}
		data, err := backup.Create(o.dataDir, func(p string) error { return e.St.Snapshot(p, logs) },
			backup.Manifest{Version: version, Schema: store.SchemaVersion(), Host: e.Setting("server_host"), WithLogs: logs}, pw)
		if err != nil {
			fatal("%v", err)
		}
		if err := os.WriteFile(file, data, 0o600); err != nil {
			fatal("%v", err)
		}
		e.Log("warn", "Sicherung über die Kommandozeile geschrieben: "+file)
		fmt.Printf("Sicherung geschrieben: %s (%d KB)\n", file, (len(data)+1023)/1024)
	case "restore":
		data, err := os.ReadFile(file)
		if err != nil {
			fatal("%v", err)
		}
		arc, err := backup.Open(data, askPassword("Passwort der Sicherung: "))
		if err != nil {
			fatal("%v", err)
		}
		if err := backup.Stage(o.dataDir, arc, store.CheckBackupDB); err != nil {
			fatal("Sicherung abgelehnt: %v", err)
		}
		m := arc.Manifest
		e.Log("warn", "Sicherung über die Kommandozeile zum Einspielen abgelegt: "+file)
		fmt.Printf("Sicherung vom %s (Panel %s, %d Dateien) geprüft und abgelegt.\n", time.Unix(m.Created, 0).Format("02.01.2006 15:04"), m.Version, len(m.Files))
		fmt.Println("Eingespielt wird beim nächsten Start:  systemctl restart vpnpanel")
	default:
		fmt.Print(usage)
		os.Exit(1)
	}
}
