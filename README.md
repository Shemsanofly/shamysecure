# ShamySecure

Secure file transfer between computers, written in Python.

One computer runs as a **server** (a relay). Other computers run as **clients**, connect to it, and see each other by `username@hostname`. Any client can send files to any other client. Every file is encrypted with **ChaCha20** using a new key, and that key is exchanged securely with **RSA**.

The server only forwards encrypted data. It **cannot read the files**.

```
   ____   _                                ____
  / ___| | |__    __ _  _ __ ___   _   _  / ___|   ___   ___  _   _  _ __   ___
  \___ \ | '_ \  / _` || '_ ` _ \ | | | | \___ \  / _ \ / __|| | | || '__| / _ \
   ___) || | | || (_| || | | | | || |_| |  ___) ||  __/| (__ | |_| || |   |  __/
  |____/ |_| |_| \__,_||_| |_| |_| \__, | |____/  \___| \___| \__,_||_|    \___|
                                   |___/
```

---

## Features

- Server mode and client mode in one script
- See connected computers by username, hostname, IP and OS
- Send a file, or every file in a folder, to any connected computer
- Accept or reject incoming files (press **Enter** to accept, **n** to reject)
- **ChaCha20** stream cipher for file encryption, with a new 256-bit key for every file
- **RSA-2048 OAEP** to encrypt each file key for the receiver
- **RSA-PSS signatures**, so the receiver knows who sent the file and that it was not changed
- **Challenge-response handshake**, so every computer proves it owns its private key
- **Trust On First Use (TOFU)**: remembers key fingerprints and warns if a key changes (possible man-in-the-middle)
- Safe filenames (blocks `../../` path tricks), a disk space check, and a transfer log
- Optional password protection for the private key

---

## Installation

You need Python 3.8 or newer.

```bash
git clone https://github.com/ms3c/shamysecure.git
cd shamysecure
pip install cryptography
```

---

## Usage

### 1. Start the server

Run this on a computer that all clients can reach, such as a lab PC or a VPS:

```bash
python secure_transfer.py server
```

The server prints its IP address and the command clients should use.
Make sure the port (default **5050**) is open in the firewall.

### 2. Start the clients

On each computer that wants to send or receive files:

```bash
python secure_transfer.py client --host <server-ip>
```

### 3. Send a file

On the client, choose **2) Send a file**, pick the computer, then type the path of the file.
The other person sees:

```
[?] alice@alice-laptop wants to send you 'report.pdf' (1.2 MB).  Press Enter to accept, n to reject.
```

After the transfer, the file is in the `received/` folder.

### Options

| Option | Meaning | Default |
|---|---|---|
| `server` / `client` | Which mode to run | (required) |
| `--host` | Server IP address (client mode) | `127.0.0.1` |
| `--port` | TCP port | `5050` |
| `--keys` | Folder for the RSA keys | `keys` |
| `--downloads` | Folder for received files | `received` |
| `--auto-accept` | Accept incoming files without asking | off |
| `--password` | Protect a **new** private key with a password | off |
| `--name` | Show this name instead of the hostname (handy for demos on one PC) | hostname |

### Demo on one computer

Open 3 terminals:

```bash
python secure_transfer.py server --keys srv_keys
python secure_transfer.py client --keys alice_keys --downloads alice_recv --name alice
python secure_transfer.py client --keys bob_keys   --downloads bob_recv   --name bob
```

---

## Menus

**Client**

```
 1) Show online computers
 2) Send a file
 3) Send all files in a folder
 4) Incoming file requests
 5) Transfers
 6) My info / fingerprint
 7) Trusted computers
 8) Settings
 9) Disconnect from server
 0) Quit
```

**Server**

```
 1) Show connected computers
 2) Relay activity
 3) My info / fingerprint
 4) Trusted computers
 5) Disconnect a computer
 0) Stop server
```

---

## How it works

### Architecture

```
  +-----------+         +-------------------+         +-----------+
  |  Client A | <-----> |   Relay  Server   | <-----> |  Client B |
  |  (alice)  |   TCP   | forwards messages |   TCP   |   (bob)   |
  +-----------+         | can't read files  |         +-----------+
                        +-------------------+
```

Clients connect to the server. The server tells every client who else is online
and forwards messages between them. The encryption is **end-to-end**, from client to client.

### 1. Handshake (client <-> server)

1. Both sides send `HELLO` with their hostname, username, OS, RSA public key and a random 32-byte challenge.
2. Each side signs the other side's challenge with its private key and sends it back (`PROOF`).
   This proves it really owns the key and is not just replaying someone else's public key.
3. The key fingerprint is compared with the one saved last time (`keys/known_peers.json`).
   If it changed, the connection is refused with a man-in-the-middle warning.

### 2. Sending a file (client A -> client B)

```
 A                                   B
 |-- FILE_OFFER (name, size) ------->|   B presses Enter
 |<-------------------- FILE_ACCEPT -|
 |                                   |
 | new random ChaCha20 key + nonce   |
 | key encrypted with B's RSA key    |
 |-- FILE_START (enc. key, nonce) -->|   B decrypts key with its private key
 |-- FILE_CHUNK (64 KB, encrypted) ->|   B decrypts and writes to .part file
 |-- FILE_CHUNK ...                ->|
 |-- FILE_END (RSA signature) ------>|   B checks signature with A's public key
 |<-- FILE_RESULT (ok / failed) -----|   bad signature -> file deleted
```

### Cryptography used

| Purpose | Algorithm |
|---|---|
| File encryption | ChaCha20 (256-bit key, 96-bit nonce, new key per file) |
| Key exchange | RSA-2048 with OAEP padding (SHA-256) |
| Authentication and integrity | RSA-PSS signature (SHA-256) over the key, nonce, file info and all encrypted chunks |
| Handshake | RSA-PSS signature over a random 32-byte challenge |
| Fingerprints | SHA-256 of the public key |
| Randomness | `os.urandom` (the operating system's secure random generator) |

All algorithms come from the [`cryptography`](https://cryptography.io) library. None of the crypto is written by hand.

---

## Security analysis

### What is protected

| Attack | Protection |
|---|---|
| Someone sniffing the network | Files are encrypted with ChaCha20 |
| Curious or hacked server | The file key is encrypted for the receiver only, so the server can't decrypt it |
| Changing data in transit (even by the server) | The RSA signature fails and the receiver deletes the file |
| Pretending to be another computer | The challenge-response handshake plus a signature on every file |
| Swapping keys (man-in-the-middle) | TOFU fingerprint check, with a warning when a key changes |
| Malicious filenames (`../../etc/passwd`) | The filename is cleaned before saving |
| Files nobody asked for | The receiver must accept first, otherwise the data is ignored |
| Disk filling attack | Free space is checked before accepting |

### Known limitations

- **First connection:** TOFU can't detect a man-in-the-middle the very first time.
  Users should compare fingerprints (menu **6**) by phone or in person.
- **Metadata:** the server can see who sends to whom, the file names and the sizes, but not the content.
- **The server connection itself is not encrypted.** Only file contents are. TLS could be added.
- **ChaCha20 has no built-in integrity check.** The project adds RSA signatures for that.
  ChaCha20-Poly1305 (AEAD) would be the more modern choice.
- **No forward secrecy:** if a private key is stolen later, recorded transfers could be decrypted.
  Ephemeral Diffie-Hellman (X25519) would fix this.
- **Private keys** are saved unencrypted unless `--password` is used.
- **Python can't securely wipe** keys from memory.

---

## Project structure

| File | What it does |
|---|---|
| `crypto_utils.py` | RSA keys, OAEP, PSS signatures, ChaCha20, fingerprints, hashing |
| `network_utils.py` | Message framing over TCP (4-byte length + JSON), connection classes, helpers |
| `secure_core.py` | Handshake, relay server, client logic, sending and receiving files |
| `secure_transfer.py` | Command line options, ASCII banner, server and client menus |

Folders created when you run it (not uploaded to git):

| Folder | Contents |
|---|---|
| `keys/` | `private_key.pem`, `public_key.pem`, `known_peers.json` |
| `received/` | Received files and `transfer_log.txt` |

---

## Testing that was done

- Transfers between two clients through the server, both directions; the SHA-256 of sent and received files match
- A modified server flipping one bit in a relayed chunk: the receiver reports "bad signature" and deletes the file
- A client coming back with a new key: the connection is refused with a "key CHANGED" warning
- Sending data for a file that was never accepted: the data is ignored
- Filenames like `../../etc/passwd`, `..\..\win.ini` and terminal escape codes are cleaned

---

## Future work

- TLS for the client-server connection
- X25519 key exchange for forward secrecy
- ChaCha20-Poly1305 instead of ChaCha20 plus a signature
- Encrypting file names and sizes so the server can't see them
- A GUI (Tkinter)
- Resuming interrupted transfers

---

*3rd year Cyber Security project.*
