# Security

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository (Security → Report a vulnerability). Do not open a public issue for anything that could help an attacker.

## Design

### Components and trust

| Component | Runs as | Trusted for |
|---|---|---|
| `omapasskeyd` | user `omapasskey`, sandboxed by systemd | everything: CTAP, PIN checks, key use, user presence |
| `omapasskey` CLI | you, or root with sudo | administration over a root-only socket |
| Omarchy plugin (`ui/`) | you, inside omarchy-shell | nothing: it only displays a read-only event stream |
| Setup script | you, with sudo | installing the above once |

The service never reads anything from the desktop. The status socket is write-only from the service's side; whatever a client sends is discarded. The admin socket accepts only UID 0.

### Key hierarchy

```
PIN ──LEFT(SHA-256,16)──HKDF(salt)──► auth value of a TPM sealed object
                                        (dictionary-attack protected)
                                              │ unseals
                                              ▼
                                   master secret G (32 random bytes,
                                   OS RNG XOR TPM RNG)
                                    │                       │
                         HKDF "key-auth"            HKDF "metadata"
                                    ▼                       ▼
            auth value of every credential key     AES-256-GCM key for site
            (P-256 ECDSA and HMAC keys created       and account names
             in the TPM, fixedTPM|fixedParent)
```

- The PIN never touches a disk and is never compared in software: the TPM decides, and wrong guesses count against its lockout.
- G exists in memory only between a successful PIN check and the end of that ceremony (at most 30 s for registration and sign-in, 10 min for credential management), then it is overwritten.
- Credential keys are children of the TCG reference ECC storage root key, which is recreated from the TPM's owner seed at every start; nothing is stored in TPM NV memory.
- TPM sessions are salted HMAC sessions with parameter encryption, so auth values and secrets never cross the TPM bus in the clear.
- On disk (`/var/lib/omapasskey/state.json`, mode 0600) there are: the sealed master secret, the PIN retry counter, and per credential its random 32-byte ID, the SHA-256 of the site's RP ID, TPM-wrapped key blobs, the public key and the encrypted account data.

### User presence

A CTAP "touch" is Left Shift + Right Shift held together on one keyboard whose sysfs device path is on a physical bus (not under `/sys/devices/virtual`). The keyboards are opened only while a confirmation is pending, the press must start after the prompt appears, and Esc cancels. Software-generated input — uinput (ydotool, input-remapper, remote desktops), uhid (including Bluetooth LE keyboards), Wayland virtual keyboards — cannot satisfy it.

Presence is collected **before** a PIN is checked, so software cannot spend PIN retries, and once per ceremony: the press that accompanied the PIN also covers the registration or sign-in it authorises (within 30 s).

### The passkey manager

The right-click manager sends the PIN to the service over `/run/omapasskey/manage.sock` (only the configured desktop users may connect). The service answers only after the confirm keys are pressed on a physical keyboard, and the same PIN retry counter and TPM lockout apply. The PIN is typed into the desktop shell, which runs as you — like any PIN prompt on a Linux desktop — but knowing it is never enough without the key press.

The confirm-key combination (default Left Shift + Right Shift) is set in the root-owned `/etc/omapasskey/omapasskey.conf` (`confirm_keys`), so software running as you cannot weaken it.

### Deliberate deviations from CTAP 2.1

- `alwaysUv` is permanently on: every registration and every sign-in needs the PIN, even if the site asks for no user verification.
- Silent assertions (`up=false`) made without a pinUvAuthToken return a fixed, never-verifying signature. Browsers use such probes only to find out whether a credential exists, which still works; they cannot be turned into a login. Discovery of usernameless credentials without the PIN returns nothing.
- `authenticatorReset` and `setPIN` require the physical key press; reset is allowed at any time, not only within 10 s of power-up.
- Three consecutive wrong PINs block PIN entry for 30 s (a virtual key cannot be unplugged to "power cycle" it).

### Installation trust

The setup script runs from the plugin folder, which belongs to you, and uses sudo. It checks the two downloaded binaries against SHA-256 sums pinned in the same folder, and the published binaries are reproducible and carry signed build provenance. But a program that can already write to your plugin folder could change the script, the unit file or the pinned sums before you run it. Install and update only from a session you trust; to check independently, compare the installed binaries with the release (`gh attestation verify /usr/local/lib/omapasskey/omapasskeyd --repo Divanyx/omapasskey`) and the unit file with the tagged source. Once installed, nothing in the plugin folder is trusted by the service.

### Known limits

- The TPM's dictionary-attack lockout limits PIN guesses by root only if the TPM's lockout authorization is set. Many TPMs ship with it empty; then root can reset the counter (TPM2_DictionaryAttackLockReset) and keep guessing against the TPM at its speed. `sudo omapasskey tpm protect` sets a random lockout password (shown once, never stored); `omapasskey doctor` and `omapasskey status` report the state, and the service logs a warning at start.

- Root (or any process able to read the service's memory or to replace its binary) can capture the PIN when you next type it. Without the PIN, root can neither use nor export keys.
- The prompt is drawn by the desktop shell, which runs as you. Software running as you could draw a misleading prompt; the browser's own dialog names the site too.
- If the TPM's owner hierarchy is cleared or the TPM replaced, every credential is lost.
