# secure_core.py
# The heart of the project:
#   BaseNode    -> things both sides need (keys, handshake, trusted keys)
#   RelayServer -> server mode, connects clients together, can NOT read files
#   ClientNode  -> client mode, sees other clients and sends/receives files

import os
import json
import time
import uuid
import socket
import shutil
import hashlib
import getpass
import platform
import threading

import crypto_utils as cu
import network_utils as nu

PROTOCOL_VERSION = 2
CHUNK_SIZE = 64 * 1024          # 64 KB per encrypted chunk
OFFER_TIMEOUT = 120             # seconds to wait for the other side to accept
MAX_CLIENTS = 20
MAX_NAME_LENGTH = 64
MAX_ACTIVITY = 50
KNOWN_PEERS_FILE = "known_peers.json"
LOG_FILE = "transfer_log.txt"


# ---------------- small helpers ----------------

def clean_text(text, max_length=MAX_NAME_LENGTH):
    # remove control characters so nobody can mess with our terminal
    if not isinstance(text, str):
        return "unknown"
    text = "".join(ch for ch in text if ch.isprintable())
    text = text.strip()[:max_length]
    return text if text else "unknown"


def safe_filename(name):
    # never trust a filename from the network (no ../../ tricks)
    name = clean_text(name, 200)
    name = name.replace("\\", "/")
    name = os.path.basename(name)
    for bad in [":", "*", "?", '"', "<", ">", "|"]:
        name = name.replace(bad, "_")
    if name in ["", ".", ".."] or name.startswith("."):
        name = "received_" + name.strip(".")
    return name if name != "received_" else "received_file"


def unique_path(folder, filename):
    # file.txt -> file (1).txt -> file (2).txt ...
    path = os.path.join(folder, filename)
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(filename)
    number = 1
    while True:
        path = os.path.join(folder, "%s (%d)%s" % (base, number, ext))
        if not os.path.exists(path):
            return path
        number += 1


def now_text():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def remove_file(path):
    try:
        os.remove(path)
    except OSError:
        pass


# =====================================================================
# BaseNode
# =====================================================================

class BaseNode:

    def __init__(self, keys_folder, use_password=False, display_name=None):
        self.keys_folder = keys_folder
        self.running = True
        self.lock = threading.Lock()
        os.makedirs(self.keys_folder, exist_ok=True)

        # our identity
        self.private_key = cu.load_or_create_rsa_keys(keys_folder, use_password)
        self.public_key = self.private_key.public_key()
        self.public_key_text = cu.public_key_to_text(self.public_key)
        self.fingerprint = cu.get_fingerprint(self.public_key)
        self.hostname = clean_text(display_name) if display_name else socket.gethostname()
        self.username = getpass.getuser()
        self.os_name = platform.system() + " " + platform.release()

        self.known_peers = self.load_known_peers()

    def notify(self, text):
        # messages from background threads
        print("\n" + text, flush=True)

    # ---------- known keys (Trust On First Use) ----------

    def known_peers_path(self):
        return os.path.join(self.keys_folder, KNOWN_PEERS_FILE)

    def load_known_peers(self):
        try:
            with open(self.known_peers_path(), "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
        return {}

    def save_known_peers(self):
        with open(self.known_peers_path(), "w") as f:
            json.dump(self.known_peers, f, indent=2)

    def check_known_peer(self, name, fingerprint):
        # returns "new", "trusted" or "changed"
        with self.lock:
            entry = self.known_peers.get(name)
            if entry is None:
                self.known_peers[name] = {"fingerprint": fingerprint, "first_seen": now_text()}
                self.save_known_peers()
                return "new"
            if entry["fingerprint"] == fingerprint:
                return "trusted"
            return "changed"

    def forget_peer(self, name):
        with self.lock:
            if name in self.known_peers:
                del self.known_peers[name]
                self.save_known_peers()
                return True
        return False

    def key_changed_warning(self, name, new_fingerprint, what):
        old = self.known_peers[name]["fingerprint"]
        self.notify(
            "[!!!] WARNING: the key of " + name + " has CHANGED!\n"
            "      old: " + old + "\n"
            "      new: " + new_fingerprint + "\n"
            "      This could be a man-in-the-middle attack. " + what + "\n"
            "      If they really made a new key, remove them from trusted computers."
        )

    # ---------- handshake (same for client and server) ----------

    def handshake(self, sock, address):
        sock.settimeout(nu.HANDSHAKE_TIMEOUT)

        # 1) both sides send HELLO with their public key and a random challenge
        my_challenge = cu.new_challenge()
        nu.send_json(sock, {
            "type": nu.HELLO,
            "version": PROTOCOL_VERSION,
            "hostname": self.hostname,
            "username": self.username,
            "os": self.os_name,
            "public_key": self.public_key_text,
            "challenge": nu.b64encode(my_challenge),
        })

        hello = nu.recv_json(sock)
        if hello["type"] != nu.HELLO:
            raise ConnectionError("expected HELLO, got " + clean_text(hello["type"]))
        if hello.get("version") != PROTOCOL_VERSION:
            raise ConnectionError("other side uses a different protocol version")
        for field in ["hostname", "username", "os", "public_key", "challenge"]:
            if not isinstance(hello.get(field), str):
                raise ConnectionError("HELLO is missing field: " + field)

        peer_key_text = hello["public_key"]
        peer_key = cu.public_key_from_text(peer_key_text)

        # 2) sign their challenge to prove we really own our private key
        their_challenge = nu.b64decode(hello["challenge"])
        if len(their_challenge) != cu.CHALLENGE_SIZE:
            raise ConnectionError("bad challenge size")
        my_signature = cu.sign_challenge(self.private_key, their_challenge, self.public_key_text)
        nu.send_json(sock, {"type": nu.PROOF, "signature": nu.b64encode(my_signature)})

        # 3) check their signature on our challenge
        proof = nu.recv_json(sock)
        if proof["type"] != nu.PROOF:
            raise ConnectionError("expected PROOF")
        their_signature = nu.b64decode(proof["signature"])
        if not cu.verify_challenge(peer_key, their_signature, my_challenge, peer_key_text):
            raise ConnectionError("other side could not prove it owns its private key")

        fingerprint = cu.get_fingerprint(peer_key)
        conn = nu.Connection(
            sock=sock,
            address=address,
            hostname=clean_text(hello["hostname"]),
            username=clean_text(hello["username"]),
            os_name=clean_text(hello["os"]),
            public_key=peer_key,
            fingerprint=fingerprint,
        )

        # 4) Trust On First Use: compare with the fingerprint we saw last time
        status = self.check_known_peer(conn.name(), fingerprint)
        if status == "changed":
            self.key_changed_warning(conn.name(), fingerprint, "Connection refused.")
            raise ConnectionError("key of " + conn.name() + " changed")
        if status == "new":
            self.notify("[!] First time seeing " + conn.name() + ", fingerprint: " + fingerprint)

        sock.settimeout(None)
        return conn


# =====================================================================
# RelayServer
# =====================================================================

class RelayServer(BaseNode):
    # Clients connect here. The server only forwards their messages.
    # The file keys are encrypted for the receiver, so the server can't read files.

    def __init__(self, keys_folder, use_password=False, display_name=None):
        BaseNode.__init__(self, keys_folder, use_password, display_name)
        self.server_socket = None
        self.list_seq = 0           # numbers the peer lists so old ones are ignored
        self.clients = {}           # peer_id -> Connection
        self.next_id = 1
        self.activity = []          # last things that happened (for the menu)

    def add_activity(self, text):
        with self.lock:
            self.activity.append(time.strftime("%H:%M:%S") + "  " + text)
            if len(self.activity) > MAX_ACTIVITY:
                self.activity.pop(0)

    def get_activity(self):
        with self.lock:
            return list(self.activity)

    def get_clients(self):
        with self.lock:
            return list(self.clients.values())

    # ---------- start / stop ----------

    def start(self, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        self.server_socket = server
        t = threading.Thread(target=self.accept_loop, daemon=True)
        t.start()

    def accept_loop(self):
        while self.running:
            try:
                sock, address = self.server_socket.accept()
            except OSError:
                break
            t = threading.Thread(target=self.handle_client, args=(sock, address), daemon=True)
            t.start()

    def shutdown(self):
        self.running = False
        for conn in self.get_clients():
            self.kick(conn)
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass

    def kick(self, conn):
        try:
            conn.send_json({"type": nu.BYE})
        except OSError:
            pass
        conn.close()

    # ---------- one thread per client ----------

    def handle_client(self, sock, address):
        try:
            conn = self.handshake(sock, address)
        except Exception as e:
            self.notify("[!] Handshake with " + address[0] + " failed: " + str(e))
            self.add_activity("handshake failed from " + address[0] + ": " + str(e))
            sock.close()
            return

        with self.lock:
            if len(self.clients) >= MAX_CLIENTS:
                conn = None
            else:
                conn_id = str(self.next_id)
                self.next_id += 1
        if conn is None:
            self.notify("[!] Server full, dropped connection from " + address[0])
            sock.close()
            return

        conn.peer_id = conn_id
        try:
            conn.send_json({"type": nu.WELCOME, "peer_id": conn.peer_id})
        except OSError:
            conn.close()
            return

        with self.lock:
            self.clients[conn.peer_id] = conn
        self.notify("[+] Client connected: " + str(conn) + "  [" + conn.os_name + "]")
        self.add_activity(conn.name() + " connected from " + conn.ip())
        self.broadcast_peer_list()

        reason = "disconnected"
        try:
            while conn.alive:
                msg = nu.recv_json(conn.sock)
                if msg["type"] == nu.RELAY:
                    self.relay(conn, msg)
                elif msg["type"] == nu.BYE:
                    reason = "left"
                    break
        except (ConnectionError, OSError) as e:
            if conn.alive:
                reason = str(e)
        except (ValueError, KeyError, TypeError) as e:
            reason = "protocol error: " + str(e)
        finally:
            with self.lock:
                self.clients.pop(conn.peer_id, None)
            conn.close()
            if self.running:
                self.notify("[-] Client " + conn.name() + " " + reason)
                self.add_activity(conn.name() + " " + reason)
                self.broadcast_peer_list()

    # ---------- telling everyone who is online ----------

    def broadcast_peer_list(self):
        with self.lock:
            self.list_seq += 1
            seq = self.list_seq
        clients = self.get_clients()
        for conn in clients:
            others = []
            for other in clients:
                if other is conn:
                    continue    # don't send a client to itself
                others.append({
                    "peer_id": other.peer_id,
                    "hostname": other.hostname,
                    "username": other.username,
                    "os": other.os_name,
                    "ip": other.ip(),
                    "public_key": cu.public_key_to_text(other.public_key),
                })
            conn.send_json_in_background({"type": nu.PEER_LIST, "seq": seq, "peers": others})

    # ---------- forwarding ----------

    def relay(self, sender, msg):
        target_id = str(msg.get("to"))
        inner = msg.get("msg")
        if not isinstance(inner, dict) or not isinstance(inner.get("type"), str):
            raise ValueError("bad RELAY message")

        with self.lock:
            target = self.clients.get(target_id)

        if target is None or target is sender:
            sender.send_json_in_background({"type": nu.RELAY_FAILED, "to": target_id,
                                            "transfer_id": inner.get("transfer_id")})
            return

        try:
            target.send_json({"type": nu.RELAY, "from": sender.peer_id, "msg": inner})
        except OSError:
            sender.send_json_in_background({"type": nu.RELAY_FAILED, "to": target_id,
                                            "transfer_id": inner.get("transfer_id")})
            return

        # statistics: the server sees WHO talks to WHO and file names, not the content
        sender.messages_relayed += 1
        if inner["type"] == nu.FILE_CHUNK:
            sender.bytes_relayed += len(str(inner.get("data", ""))) * 3 // 4
        elif inner["type"] == nu.FILE_OFFER:
            sender.files_offered += 1
            size = inner.get("size")
            size_text = nu.format_size(size) if isinstance(size, int) else "?"
            self.add_activity("%s -> %s : offers '%s' (%s)" % (
                sender.name(), target.name(), clean_text(inner.get("filename"), 40), size_text))
        elif inner["type"] == nu.FILE_RESULT:
            result = "verified OK" if inner.get("ok") else "FAILED check"
            self.add_activity("%s <- %s : %s" % (target.name(), sender.name(), result))


# =====================================================================
# Transfer
# =====================================================================

class Transfer:
    # info about one file transfer (sent or received)

    def __init__(self, transfer_id, direction, peer, filename, size):
        self.id = transfer_id
        self.direction = direction      # "send" or "receive"
        self.peer = peer
        self.peer_name = peer.name()
        self.filename = filename        # name shown to the user / saved on disk
        self.wire_name = filename       # exact name used in the signature
        self.size = size
        self.done_bytes = 0
        self.status = "created"
        self.message = ""
        self.sha256 = ""
        self.source_path = ""
        self.saved_path = ""
        self.started = time.time()
        self.finished = None
        # only used while receiving
        self.part_path = ""
        self.file = None
        self.decryptor = None
        self.signed_hash = None
        self.plain_hash = None

    def progress(self):
        if self.size == 0:
            return 100
        return int(self.done_bytes * 100 / self.size)

    def elapsed(self):
        end = self.finished if self.finished else time.time()
        return end - self.started

    def is_finished(self):
        return self.status in ["done", "failed", "rejected"]

    def finish(self, status, message=""):
        if self.is_finished():
            return
        self.status = status
        self.message = message
        self.finished = time.time()


# =====================================================================
# ClientNode
# =====================================================================

class ClientNode(BaseNode):

    def __init__(self, keys_folder, downloads_folder, auto_accept=False, use_password=False,
                 display_name=None):
        BaseNode.__init__(self, keys_folder, use_password, display_name)
        self.downloads_folder = downloads_folder
        self.auto_accept = auto_accept
        os.makedirs(self.downloads_folder, exist_ok=True)

        self.server = None          # Connection to the relay server
        self.my_id = ""
        self.last_list_seq = 0
        self.peers = {}             # peer_id -> RemotePeer (other clients)
        self.transfers = []
        self.incoming_offers = {}   # (peer_id, transfer_id) -> Transfer waiting for the user
        self.accepted = {}          # (peer_id, transfer_id) -> Transfer we said yes to
        self.receiving = {}         # (peer_id, transfer_id) -> Transfer being received
        self.outgoing_waits = {}    # transfer_id -> dict with Event + answer

    # ---------- connection to the server ----------

    def is_connected(self):
        return self.server is not None and self.server.alive

    def connect(self, host, port):
        sock = socket.create_connection((host, port), timeout=10)
        try:
            conn = self.handshake(sock, (host, port))
            sock.settimeout(nu.HANDSHAKE_TIMEOUT)
            welcome = nu.recv_json(sock)
            if welcome["type"] != nu.WELCOME:
                raise ConnectionError("server did not welcome us")
            sock.settimeout(None)
        except Exception:
            sock.close()
            raise

        self.my_id = clean_text(str(welcome.get("peer_id")), 20)
        self.last_list_seq = 0
        self.server = conn
        self.notify("[+] Connected to server " + str(conn))
        t = threading.Thread(target=self.receive_loop, args=(conn,), daemon=True)
        t.start()
        return conn

    def disconnect(self):
        if self.server:
            try:
                self.server.send_json({"type": nu.BYE})
            except OSError:
                pass
            self.server.close()

    def shutdown(self):
        self.running = False
        self.disconnect()

    def send_to_peer(self, peer, inner):
        # wrap a message so the server forwards it to another client
        self.server.send_json({"type": nu.RELAY, "to": peer.peer_id, "msg": inner})

    def send_to_peer_in_background(self, peer, inner):
        if self.server:
            self.server.send_json_in_background({"type": nu.RELAY, "to": peer.peer_id, "msg": inner})

    # ---------- other clients ----------

    def get_peers(self):
        with self.lock:
            return list(self.peers.values())

    def update_peer_list(self, entries):
        if not isinstance(entries, list):
            raise ValueError("bad PEER_LIST")

        with self.lock:
            old_peers = dict(self.peers)
        new_peers = {}

        for entry in entries:
            peer_id = clean_text(str(entry.get("peer_id")), 20)
            if peer_id in old_peers:
                new_peers[peer_id] = old_peers[peer_id]
                continue
            try:
                key = cu.public_key_from_text(entry["public_key"])
            except (KeyError, ValueError, TypeError):
                continue    # skip broken entries
            fingerprint = cu.get_fingerprint(key)
            peer = nu.RemotePeer(
                peer_id=peer_id,
                hostname=clean_text(entry.get("hostname")),
                username=clean_text(entry.get("username")),
                os_name=clean_text(entry.get("os")),
                ip=clean_text(entry.get("ip"), 45),
                public_key=key,
                fingerprint=fingerprint,
            )

            # the server gives us the keys, so we check them ourselves (TOFU)
            status = self.check_known_peer(peer.name(), fingerprint)
            if status == "changed":
                peer.trusted = False
                self.key_changed_warning(peer.name(), fingerprint, "Transfers with them are blocked.")
            elif status == "new":
                self.notify("[+] " + peer.name() + " is online (new computer)\n"
                            "    Their fingerprint: " + fingerprint + "\n"
                            "    Check it with them (phone / in person) before sending secrets!")
            else:
                self.notify("[+] " + peer.name() + " is online")
            new_peers[peer_id] = peer

        with self.lock:
            self.peers = new_peers

        for peer_id, peer in old_peers.items():
            if peer_id not in new_peers:
                self.notify("[-] " + peer.name() + " went offline")
                self.cleanup_peer(peer, "peer went offline")

    def cleanup_peer(self, peer, reason):
        with self.lock:
            for wait in self.outgoing_waits.values():
                if wait["peer"] is peer:
                    wait["accepted"] = False
                    wait["reason"] = reason
                    wait["event"].set()
            for table in [self.incoming_offers, self.accepted]:
                for key in list(table.keys()):
                    if table[key].peer is peer:
                        table.pop(key).finish("failed", reason)
            receiving = [k for k in self.receiving if self.receiving[k].peer is peer]
        for key in receiving:
            self.abort_receive(key, reason, tell_sender=False)
        for t in self.get_transfers():
            if t.peer is peer and not t.is_finished():
                t.finish("failed", reason)

    # ---------- receive loop (messages from the server) ----------

    def receive_loop(self, conn):
        reason = "connection lost"
        try:
            while conn.alive:
                msg = nu.recv_json(conn.sock)
                kind = msg["type"]
                if kind == nu.PEER_LIST:
                    seq = int(msg.get("seq", 0))
                    if seq > self.last_list_seq:     # ignore old lists
                        self.last_list_seq = seq
                        self.update_peer_list(msg.get("peers"))
                elif kind == nu.RELAY:
                    self.handle_relayed(str(msg.get("from")), msg.get("msg"))
                elif kind == nu.RELAY_FAILED:
                    self.on_relay_failed(msg)
                elif kind == nu.BYE:
                    reason = "server closed the connection"
                    break
        except (ConnectionError, OSError) as e:
            if conn.alive:
                reason = str(e)
        except (ValueError, KeyError, TypeError) as e:
            reason = "protocol error: " + str(e)
        finally:
            conn.close()
            for peer in self.get_peers():
                self.cleanup_peer(peer, "disconnected from server")
            with self.lock:
                self.peers = {}
            if self.running:
                self.notify("[-] Disconnected from server: " + reason + "  (use 'r' to reconnect)")

    def handle_relayed(self, from_id, inner):
        with self.lock:
            peer = self.peers.get(from_id)
        if peer is None or not isinstance(inner, dict):
            return      # unknown sender, ignore

        kind = inner.get("type")
        transfer_id = clean_text(str(inner.get("transfer_id")), 40)
        key = (peer.peer_id, transfer_id)

        if not peer.trusted:
            if kind == nu.FILE_OFFER:
                self.send_to_peer_in_background(peer, {"type": nu.FILE_REJECT, "transfer_id": transfer_id,
                                                       "reason": "your key is not trusted"})
            return

        try:
            if kind == nu.FILE_OFFER:
                self.on_file_offer(peer, transfer_id, inner)
            elif kind == nu.FILE_ACCEPT:
                self.on_offer_answer(peer, transfer_id, True, "")
            elif kind == nu.FILE_REJECT:
                self.on_offer_answer(peer, transfer_id, False, inner.get("reason", ""))
            elif kind == nu.FILE_START:
                self.on_file_start(peer, key, inner)
            elif kind == nu.FILE_CHUNK:
                self.on_file_chunk(key, inner)
            elif kind == nu.FILE_END:
                self.on_file_end(peer, key, inner)
            elif kind == nu.FILE_RESULT:
                self.on_file_result(peer, transfer_id, inner)
        except (ValueError, KeyError, TypeError, OSError) as e:
            # one bad transfer should not kill the whole connection
            self.notify("[!] Bad message from " + peer.name() + ": " + str(e))
            if key in self.receiving:
                self.abort_receive(key, "bad data: " + str(e))

    def on_relay_failed(self, msg):
        transfer_id = msg.get("transfer_id")
        with self.lock:
            wait = self.outgoing_waits.get(transfer_id)
        if wait:
            wait["accepted"] = False
            wait["reason"] = "computer is not connected any more"
            wait["event"].set()
        t = self.find_transfer(transfer_id, "send")
        if t:
            t.finish("failed", "computer is not connected any more")

    # ---------- transfers list ----------

    def add_transfer(self, transfer):
        with self.lock:
            self.transfers.append(transfer)

    def get_transfers(self):
        with self.lock:
            return list(self.transfers)

    def clear_finished_transfers(self):
        with self.lock:
            self.transfers = [t for t in self.transfers if not t.is_finished()]

    def find_transfer(self, transfer_id, direction):
        with self.lock:
            for t in self.transfers:
                if t.id == transfer_id and t.direction == direction:
                    return t
        return None

    def get_incoming_offers(self):
        with self.lock:
            return list(self.incoming_offers.values())

    def log_transfer(self, t):
        line = "%s | %-7s | %-25s | %-30s | %10s | %-8s | %s | %s\n" % (
            now_text(), t.direction, t.peer_name, t.filename,
            nu.format_size(t.size), t.status, t.sha256 or "-", t.message,
        )
        try:
            with open(os.path.join(self.downloads_folder, LOG_FILE), "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass

    # ---------- incoming offers ----------

    def on_file_offer(self, peer, transfer_id, msg):
        wire_name = msg["filename"]
        size = int(msg["size"])
        if not isinstance(wire_name, str) or size < 0:
            raise ValueError("bad FILE_OFFER")

        t = Transfer(transfer_id, "receive", peer, safe_filename(wire_name), size)
        t.wire_name = wire_name
        t.status = "offered"
        self.add_transfer(t)

        # do we have enough disk space?
        free = shutil.disk_usage(self.downloads_folder).free
        if size > free:
            self.reject_offer(t, "not enough disk space")
            self.notify("[!] Rejected '" + t.filename + "' from " + peer.name() + ": no disk space")
            return

        if self.auto_accept:
            self.accept_offer(t)
            self.notify("[*] Auto-accepted '" + t.filename + "' (" + nu.format_size(size) +
                        ") from " + peer.name())
        else:
            with self.lock:
                self.incoming_offers[(peer.peer_id, t.id)] = t
            self.notify("[?] " + peer.name() + " wants to send you '" + t.filename + "' (" +
                        nu.format_size(size) + ").  Press Enter to accept, n to reject.")

    def accept_offer(self, t):
        with self.lock:
            self.incoming_offers.pop((t.peer.peer_id, t.id), None)
            self.accepted[(t.peer.peer_id, t.id)] = t
        t.status = "accepted"
        self.send_to_peer_in_background(t.peer, {"type": nu.FILE_ACCEPT, "transfer_id": t.id})

    def reject_offer(self, t, reason="rejected by user"):
        with self.lock:
            self.incoming_offers.pop((t.peer.peer_id, t.id), None)
        t.finish("rejected", reason)
        self.send_to_peer_in_background(t.peer, {"type": nu.FILE_REJECT, "transfer_id": t.id,
                                                 "reason": reason})
        self.log_transfer(t)

    # ---------- receiving a file (step by step) ----------

    def on_file_start(self, peer, key, msg):
        with self.lock:
            t = self.accepted.pop(key, None)
        if t is None:
            self.notify("[!] " + peer.name() + " sent a file we never accepted, ignored")
            return

        encrypted_key = nu.b64decode(msg["encrypted_key"])
        nonce = nu.b64decode(msg["nonce"])
        if len(nonce) != cu.CHACHA_NONCE_SIZE:
            raise ValueError("bad nonce size")

        # open the ChaCha20 key with our RSA private key
        try:
            file_key = cu.rsa_decrypt(self.private_key, encrypted_key)
        except ValueError:
            t.finish("failed", "could not decrypt the file key")
            raise ValueError("could not decrypt the file key")
        if len(file_key) != cu.CHACHA_KEY_SIZE:
            raise ValueError("bad file key size")

        t.decryptor = cu.chacha20_decryptor(file_key, nonce)
        t.signed_hash = cu.TransferHasher(t.id, t.wire_name, t.size, encrypted_key, nonce)
        t.plain_hash = hashlib.sha256()
        t.part_path = os.path.join(self.downloads_folder, t.filename + "." + t.id + ".part")
        t.file = open(t.part_path, "wb")
        t.status = "receiving"
        t.started = time.time()
        with self.lock:
            self.receiving[key] = t

    def on_file_chunk(self, key, msg):
        with self.lock:
            t = self.receiving.get(key)
        if t is None:
            return
        chunk = nu.b64decode(msg["data"])
        if len(chunk) == 0 or t.done_bytes + len(chunk) > t.size:
            raise ValueError("sender sent more data than announced")
        t.signed_hash.add_chunk(chunk)
        plain = t.decryptor.update(chunk)
        t.plain_hash.update(plain)
        t.file.write(plain)
        t.done_bytes += len(chunk)

    def on_file_end(self, peer, key, msg):
        with self.lock:
            t = self.receiving.pop(key, None)
        if t is None:
            return
        t.file.close()

        if t.done_bytes != t.size:
            remove_file(t.part_path)
            t.finish("failed", "file is incomplete")
            self.send_result(t, False, "file is incomplete")
            return

        # check the RSA signature BEFORE we keep the file
        signature = nu.b64decode(msg["signature"])
        signature_ok = cu.rsa_verify(peer.public_key, signature, t.signed_hash.digest())
        t.sha256 = t.plain_hash.hexdigest()
        hash_ok = (msg.get("sha256") == t.sha256)

        if signature_ok and hash_ok:
            final_path = unique_path(self.downloads_folder, t.filename)
            os.replace(t.part_path, final_path)
            t.saved_path = final_path
            t.finish("done", "signature OK")
            self.notify("[+] Received '" + t.filename + "' from " + peer.name() +
                        " (" + nu.format_size(t.size) + ", " +
                        nu.format_speed(t.size, t.elapsed()) + ")\n"
                        "    signature OK, saved to: " + final_path + "\n"
                        "    SHA-256: " + t.sha256)
            self.send_result(t, True, "")
        else:
            remove_file(t.part_path)
            reason = "bad signature" if not signature_ok else "hash mismatch"
            t.finish("failed", reason + " - file deleted")
            self.notify("[!!!] '" + t.filename + "' from " + peer.name() + " FAILED the check (" +
                        reason + "). The file was modified or is not from them. Deleted.")
            self.send_result(t, False, reason)

    def abort_receive(self, key, reason, tell_sender=True):
        with self.lock:
            t = self.receiving.pop(key, None)
        if t is None:
            return
        if t.file:
            t.file.close()
        remove_file(t.part_path)
        t.finish("failed", reason)
        if tell_sender:
            self.send_result(t, False, reason)
        else:
            self.log_transfer(t)

    def send_result(self, t, ok, reason):
        self.send_to_peer_in_background(t.peer, {"type": nu.FILE_RESULT, "transfer_id": t.id,
                                                 "ok": ok, "reason": reason, "sha256": t.sha256})
        self.log_transfer(t)

    # ---------- sending a file ----------

    def send_file(self, peer, path):
        # runs in the background so the menu stays usable
        transfer_id = uuid.uuid4().hex[:16]
        t = Transfer(transfer_id, "send", peer, os.path.basename(path), os.path.getsize(path))
        t.source_path = path
        self.add_transfer(t)
        worker = threading.Thread(target=self.send_worker, args=(peer, t), daemon=True)
        worker.start()
        return t

    def send_worker(self, peer, t):
        wait = {"event": threading.Event(), "accepted": False, "reason": "", "peer": peer}
        with self.lock:
            self.outgoing_waits[t.id] = wait
        try:
            # 1) ask the other side first
            t.status = "waiting for accept"
            self.send_to_peer(peer, {"type": nu.FILE_OFFER, "transfer_id": t.id,
                                     "filename": t.wire_name, "size": t.size})

            if not wait["event"].wait(OFFER_TIMEOUT):
                t.finish("failed", "no answer from " + peer.name())
            elif not wait["accepted"]:
                t.finish("rejected", clean_text(wait["reason"], 100))
            else:
                # 2) they said yes, send it encrypted
                self.stream_file(peer, t)
        except OSError as e:
            t.finish("failed", str(e))
        finally:
            with self.lock:
                self.outgoing_waits.pop(t.id, None)

        if t.status in ["failed", "rejected"]:
            self.notify("[!] Sending '" + t.filename + "' to " + peer.name() + " " +
                        t.status + ": " + t.message)
            self.log_transfer(t)

    def on_offer_answer(self, peer, transfer_id, accepted, reason):
        with self.lock:
            wait = self.outgoing_waits.get(transfer_id)
        if wait is None or wait["peer"] is not peer:
            return
        wait["accepted"] = accepted
        wait["reason"] = reason if isinstance(reason, str) else ""
        wait["event"].set()

    def stream_file(self, peer, t):
        # a NEW random key and nonce for this file only
        file_key = cu.new_file_key()
        nonce = cu.new_nonce()
        encrypted_key = cu.rsa_encrypt(peer.public_key, file_key)

        encryptor = cu.chacha20_encryptor(file_key, nonce)
        signed_hash = cu.TransferHasher(t.id, t.wire_name, t.size, encrypted_key, nonce)
        plain_hash = hashlib.sha256()

        t.status = "sending"
        t.started = time.time()

        self.send_to_peer(peer, {
            "type": nu.FILE_START,
            "transfer_id": t.id,
            "encrypted_key": nu.b64encode(encrypted_key),
            "nonce": nu.b64encode(nonce),
        })

        with open(t.source_path, "rb") as f:
            while t.done_bytes < t.size:
                if t.is_finished():
                    return      # peer left or server said it failed
                block = f.read(min(CHUNK_SIZE, t.size - t.done_bytes))
                if not block:
                    raise OSError("file got smaller while sending")
                plain_hash.update(block)
                chunk = encryptor.update(block)
                signed_hash.add_chunk(chunk)
                self.send_to_peer(peer, {"type": nu.FILE_CHUNK, "transfer_id": t.id,
                                         "data": nu.b64encode(chunk)})
                t.done_bytes += len(block)

        # sign everything we sent
        signature = cu.rsa_sign(self.private_key, signed_hash.digest())
        t.sha256 = plain_hash.hexdigest()
        self.send_to_peer(peer, {
            "type": nu.FILE_END,
            "transfer_id": t.id,
            "signature": nu.b64encode(signature),
            "sha256": t.sha256,
        })

        # python can't really wipe memory, but we drop our reference to the key
        del file_key
        t.status = "waiting for confirmation"

    def on_file_result(self, peer, transfer_id, msg):
        t = self.find_transfer(transfer_id, "send")
        if t is None or t.peer is not peer:
            return
        if msg.get("ok"):
            t.finish("done", "receiver verified signature")
            self.notify("[+] '" + t.filename + "' delivered to " + peer.name() + " (" +
                        nu.format_size(t.size) + " in " + nu.format_duration(t.elapsed()) +
                        "), they verified it OK")
        else:
            t.finish("failed", "receiver says: " + clean_text(msg.get("reason", ""), 100))
            self.notify("[!] " + peer.name() + " could not verify '" + t.filename + "': " + t.message)
        self.log_transfer(t)
