// Command omapasskey manages the Omapasskey service: PIN, passkeys, status.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Divanyx/omapasskey/internal/admin"
	"github.com/Divanyx/omapasskey/internal/ctap2"
	"github.com/Divanyx/omapasskey/internal/presence"
)

var version = "dev"

const usage = `omapasskey — TPM-backed passkeys for Omarchy

Usage:
  omapasskey status            show the service state
  omapasskey watch             follow prompts and sign-ins as they happen
  omapasskey doctor            check every link of the chain
  sudo omapasskey pin set      set the PIN (first time)
  sudo omapasskey pin change   change the PIN
  sudo omapasskey list         list stored passkeys (asks for the PIN)
  sudo omapasskey delete ID    delete one passkey (ID prefix from list)
  sudo omapasskey reset        delete the PIN and ALL passkeys
  sudo omapasskey tpm protect  lock the TPM's guess counter with a recovery code
  omapasskey keys              show the key combination that confirms
  sudo omapasskey keys set K   change it, e.g. leftctrl+rightctrl (2-4 keys)
  omapasskey version
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(2)
	}
	var err error
	switch args[0] {
	case "status":
		err = cmdStatus(len(args) > 1 && args[1] == "--json")
	case "watch":
		err = cmdWatch()
	case "doctor":
		err = cmdDoctor()
	case "pin":
		if len(args) < 2 {
			err = errors.New("usage: omapasskey pin set|change")
		} else if args[1] == "set" {
			err = cmdSetPIN()
		} else if args[1] == "change" {
			err = cmdChangePIN()
		} else {
			err = errors.New("usage: omapasskey pin set|change")
		}
	case "list":
		err = cmdList()
	case "delete":
		if len(args) != 2 {
			err = errors.New("usage: omapasskey delete ID")
		} else {
			err = cmdDelete(args[1])
		}
	case "reset":
		err = cmdReset()
	case "tpm":
		if len(args) == 2 && args[1] == "protect" {
			err = cmdTPMProtect()
		} else {
			err = errors.New("usage: sudo omapasskey tpm protect")
		}
	case "keys":
		if len(args) == 3 && args[1] == "set" {
			err = cmdSetKeys(args[2])
		} else if len(args) == 1 {
			err = cmdShowKeys()
		} else {
			err = errors.New("usage: omapasskey keys [set COMBO]")
		}
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "omapasskey:", err)
		os.Exit(1)
	}
}

func needRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this needs root: run it with sudo")
	}
	return nil
}

func call(req admin.Request) (*admin.Response, error) {
	resp, err := admin.Call(admin.SocketPath, req, 60*time.Second)
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return nil, errors.New("the service is not running (systemctl status omapasskeyd)")
	}
	return resp, err
}

// readSecret reads a line from the terminal without echoing it.
func readSecret(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("a terminal is needed to type the PIN")
	}
	defer tty.Close()
	fd := int(tty.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", err
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
		return "", err
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, old)
	fmt.Fprint(tty, prompt)
	line, err := bufio.NewReader(tty).ReadString('\n')
	fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readNewPIN() (string, error) {
	for {
		pin, err := readSecret("New PIN (at least 6 characters, letters welcome): ")
		if err != nil {
			return "", err
		}
		again, err := readSecret("Repeat the new PIN: ")
		if err != nil {
			return "", err
		}
		if pin != again {
			fmt.Fprintln(os.Stderr, "The two PINs differ, once more.")
			continue
		}
		return pin, nil
	}
}

func cmdSetPIN() error {
	if err := needRoot(); err != nil {
		return err
	}
	pin, err := readNewPIN()
	if err != nil {
		return err
	}
	if _, err := call(admin.Request{Cmd: "set-pin", PIN: pin}); err != nil {
		return err
	}
	fmt.Println("PIN set. Browsers will ask for it on every passkey use.")
	return nil
}

func cmdChangePIN() error {
	if err := needRoot(); err != nil {
		return err
	}
	old, err := readSecret("Current PIN: ")
	if err != nil {
		return err
	}
	pin, err := readNewPIN()
	if err != nil {
		return err
	}
	if _, err := call(admin.Request{Cmd: "change-pin", PIN: old, NewPIN: pin}); err != nil {
		return err
	}
	fmt.Println("PIN changed.")
	return nil
}

func cmdList() error {
	if err := needRoot(); err != nil {
		return err
	}
	pin, err := readSecret("PIN: ")
	if err != nil {
		return err
	}
	resp, err := call(admin.Request{Cmd: "list", PIN: pin})
	if err != nil {
		return err
	}
	var accts []ctap2.AccountInfo
	if err := json.Unmarshal(resp.Data, &accts); err != nil {
		return err
	}
	if len(accts) == 0 {
		fmt.Println("No passkeys stored yet.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSITE\tACCOUNT\tKIND\tCREATED")
	for _, a := range accts {
		kind := "passkey"
		if !a.Discoverable {
			kind = "security key"
		}
		if a.PRF {
			kind += " +PRF"
		}
		account := a.UserName
		if account == "" {
			account = a.DisplayName
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", hex.EncodeToString(a.ID[:6]), a.RPID, account, kind,
			time.Unix(a.Created, 0).Format("02-01-2006 15:04"))
	}
	return w.Flush()
}

func cmdDelete(id string) error {
	if err := needRoot(); err != nil {
		return err
	}
	prefix, err := hex.DecodeString(id)
	if err != nil || len(prefix) < 3 {
		return errors.New("give at least the first 6 hex digits of the ID from 'omapasskey list'")
	}
	pin, err := readSecret("PIN: ")
	if err != nil {
		return err
	}
	if _, err := call(admin.Request{Cmd: "delete", PIN: pin, ID: prefix}); err != nil {
		return err
	}
	fmt.Println("Deleted. The site still lists it until you remove it there too.")
	return nil
}

func cmdReset() error {
	if err := needRoot(); err != nil {
		return err
	}
	fmt.Println("This deletes the PIN and EVERY passkey stored by Omapasskey.")
	fmt.Println("Sites will no longer accept them; you need another way to sign in there.")
	fmt.Print("Type 'delete all passkeys' to continue: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(line) != "delete all passkeys" {
		return errors.New("nothing was deleted")
	}
	if _, err := call(admin.Request{Cmd: "reset"}); err != nil {
		return err
	}
	fmt.Println("Reset. Set a new PIN with: sudo omapasskey pin set")
	return nil
}

func cmdStatus(asJSON bool) error {
	if os.Geteuid() == 0 {
		resp, err := call(admin.Request{Cmd: "status"})
		if err != nil {
			return err
		}
		if asJSON {
			fmt.Println(string(resp.Data))
			return nil
		}
		var st struct {
			Version       string              `json:"version"`
			Device        string              `json:"device"`
			AAGUID        string              `json:"aaguid"`
			Authenticator ctap2.Status        `json:"authenticator"`
			Keyboards     []presence.Keyboard `json:"keyboards"`
			TPM           *struct {
				Manufacturer    string `json:"manufacturer"`
				LockoutCounter  uint32 `json:"lockoutCounter"`
				MaxAuthFail     uint32 `json:"maxAuthFail"`
				LockoutInterval uint32 `json:"lockoutInterval"`
				InLockout       bool   `json:"inLockout"`
				LockoutAuthSet  bool   `json:"lockoutAuthSet"`
			} `json:"tpm"`
		}
		if err := json.Unmarshal(resp.Data, &st); err != nil {
			return err
		}
		a := st.Authenticator
		fmt.Printf("Omapasskey %s\n", st.Version)
		fmt.Printf("  device      /dev/%s (AAGUID %s)\n", orDash(st.Device), st.AAGUID)
		fmt.Printf("  PIN         %s, %d of 8 tries left, at least %d characters\n", yesNo(a.PINSet, "set", "NOT SET"), a.PINRetries, a.MinPINLength)
		fmt.Printf("  passkeys    %d (plus %d security-key credentials)\n", a.Discoverable, a.Total-a.Discoverable)
		if st.TPM != nil {
			fmt.Printf("  TPM         %s, lockout after %d wrong PINs (now %d)%s\n", strings.TrimSpace(st.TPM.Manufacturer),
				st.TPM.MaxAuthFail, st.TPM.LockoutCounter, yesNo(st.TPM.InLockout, ", LOCKED OUT", ""))
		}
		if st.TPM != nil {
			fmt.Printf("  root-proof  %s\n", yesNo(st.TPM.LockoutAuthSet, "yes, the TPM lockout has a password", "NO — root could reset the PIN guess limit: sudo omapasskey tpm protect"))
		}
		fmt.Printf("  keyboards   %d physical keyboard(s) can confirm\n", len(st.Keyboards))
		for _, k := range st.Keyboards {
			fmt.Printf("              - %s\n", k.Name)
		}
		return nil
	}
	conn, err := net.DialTimeout("unix", admin.StatusSocketPath, 3*time.Second)
	if err != nil {
		return errors.New("the service is not running (systemctl status omapasskeyd)")
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return errors.New("the service did not answer; is your user allowed in /etc/omapasskey/omapasskey.conf?")
	}
	if asJSON {
		fmt.Print(string(line))
		return nil
	}
	var hello struct {
		State struct {
			Version    string `json:"version"`
			PINSet     bool   `json:"pinSet"`
			PINRetries int    `json:"pinRetries"`
			Device     string `json:"device"`
			Keyboards  int    `json:"keyboards"`
		} `json:"state"`
	}
	if err := json.Unmarshal(line, &hello); err != nil {
		return err
	}
	s := hello.State
	fmt.Printf("Omapasskey %s on /dev/%s\n", s.Version, orDash(s.Device))
	fmt.Printf("  PIN         %s (%d of 8 tries left)\n", yesNo(s.PINSet, "set", "NOT SET — run: sudo omapasskey pin set"), s.PINRetries)
	fmt.Printf("  keyboards   %d physical keyboard(s) can confirm\n", s.Keyboards)
	fmt.Println("  details     sudo omapasskey status")
	return nil
}

func cmdWatch() error {
	conn, err := net.Dial("unix", admin.StatusSocketPath)
	if err != nil {
		return errors.New("the service is not running (systemctl status omapasskeyd)")
	}
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		fmt.Printf("%s  %s\n", time.Now().Format("15:04:05"), sc.Text())
	}
	return sc.Err()
}

func cmdDoctor() error {
	ok := true
	check := func(good bool, what, fix string) {
		if good {
			fmt.Printf("  ✓ %s\n", what)
			return
		}
		ok = false
		fmt.Printf("  ✗ %s\n      → %s\n", what, fix)
	}
	fmt.Println("Omapasskey doctor")
	_, err := os.Stat("/dev/tpmrm0")
	check(err == nil, "TPM 2.0 resource manager (/dev/tpmrm0)", "enable the TPM (fTPM/PTT) in the firmware setup")
	_, err = os.Stat("/dev/uhid")
	check(err == nil, "uhid device (/dev/uhid)", "sudo modprobe uhid")
	active := exec.Command("systemctl", "is-active", "--quiet", "omapasskeyd").Run() == nil
	check(active, "service omapasskeyd running", "sudo systemctl enable --now omapasskeyd; journalctl -u omapasskeyd")
	conn, err := net.DialTimeout("unix", admin.StatusSocketPath, 2*time.Second)
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, rerr := bufio.NewReader(conn).ReadBytes('\n')
		conn.Close()
		check(rerr == nil, "desktop status stream reachable for this user", "add your UID to users= in /etc/omapasskey/omapasskey.conf")
		var hello struct {
			State struct {
				PINSet           bool   `json:"pinSet"`
				Device           string `json:"device"`
				LockoutProtected bool   `json:"lockoutProtected"`
			} `json:"state"`
		}
		json.Unmarshal(line, &hello)
		check(hello.State.PINSet, "PIN set", "sudo omapasskey pin set")
		check(hello.State.LockoutProtected, "PIN guess limit holds against root (TPM lockout password set)", "sudo omapasskey tpm protect")
		if hello.State.Device != "" {
			node := "/dev/" + hello.State.Device
			f, oerr := os.OpenFile(node, os.O_RDWR, 0)
			if f != nil {
				f.Close()
			}
			check(oerr == nil, "browser access to "+node, "udev did not tag the device as a security token; reboot or check 60-fido-id.rules")
		} else {
			check(false, "virtual security key present", "journalctl -u omapasskeyd")
		}
	} else {
		check(false, "desktop status stream (/run/omapasskey/status.sock)", "start the service")
	}
	kbs := presence.New(0).Keyboards()
	check(len(kbs) > 0, fmt.Sprintf("%d physical keyboard(s) to confirm with", len(kbs)), "plug in a wired keyboard; Bluetooth LE keyboards cannot confirm by design")
	if ok {
		fmt.Println("All good. Try it: https://webauthn.io (create a passkey, then sign in).")
		return nil
	}
	return errors.New("some checks failed")
}

func yesNo(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

const configPath = "/etc/omapasskey/omapasskey.conf"

func cmdShowKeys() error {
	conn, err := net.DialTimeout("unix", admin.StatusSocketPath, 3*time.Second)
	if err != nil {
		return errors.New("the service is not running (systemctl status omapasskeyd)")
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return err
	}
	var hello struct {
		State struct {
			ConfirmSpec string   `json:"confirmSpec"`
			ConfirmKeys []string `json:"confirmKeys"`
		} `json:"state"`
	}
	json.Unmarshal(line, &hello)
	fmt.Printf("%s  (%s)\n", strings.Join(hello.State.ConfirmKeys, " + "), hello.State.ConfirmSpec)
	return nil
}

func cmdSetKeys(spec string) error {
	if err := needRoot(); err != nil {
		return err
	}
	combo, err := presence.ParseCombo(spec)
	if err != nil {
		return err
	}
	w := presence.New(0)
	w.Combo = combo
	if len(w.Keyboards()) == 0 {
		return fmt.Errorf("no physical keyboard has all of %s", strings.Join(combo.Labels, " + "))
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var out []string
	replaced := false
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if k, _, ok := strings.Cut(l, "="); ok && strings.TrimSpace(k) == "confirm_keys" {
			if !replaced {
				out = append(out, "confirm_keys = "+combo.Spec)
				replaced = true
			}
			continue
		}
		out = append(out, l)
	}
	if !replaced {
		out = append(out, "# Keys pressed together to confirm a passkey use (2-4, physical keyboard).", "confirm_keys = "+combo.Spec)
	}
	tmp := configPath + ".new"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, configPath); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "restart", "omapasskeyd").CombinedOutput(); err != nil {
		return fmt.Errorf("restarting the service: %v %s", err, out)
	}
	fmt.Printf("Confirm with: %s\n", strings.Join(combo.Labels, " + "))
	return nil
}

func cmdTPMProtect() error {
	if err := needRoot(); err != nil {
		return err
	}
	fmt.Println(`This gives your TPM's lockout hierarchy a random password and shows it once.

Without it, anyone with root can reset the TPM's wrong-PIN counter and keep
guessing your passkey PIN. With it, only the holder of this code can.

Keep the code offline (password manager, paper). It is not stored anywhere.
You need it only to reset the TPM's lockout from the operating system; the
firmware's "Clear TPM" still works without it (and erases all TPM keys).`)
	fmt.Print("\nType 'protect' to continue: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(line) != "protect" {
		return errors.New("nothing was changed")
	}
	resp, err := call(admin.Request{Cmd: "tpm-protect"})
	if err != nil {
		return err
	}
	var out struct {
		Code string `json:"code"`
	}
	json.Unmarshal(resp.Data, &out)
	fmt.Printf("\nTPM lockout recovery code (write it down now):\n\n    %s\n\n", out.Code)
	return nil
}
