# network_utils.py
# Sending/receiving messages over TCP + connection classes + small helpers

import json
import socket
import struct
import base64
import threading
import time

DEFAULT_PORT = 5050
MAX_MESSAGE_SIZE = 4 * 1024 * 1024   # 4 MB max for one message
HANDSHAKE_TIMEOUT = 15               # seconds

# messages between a client and the server
HELLO = "HELLO"
PROOF = "PROOF"
WELCOME = "WELCOME"            # server -> client: your id
PEER_LIST = "PEER_LIST"        # server -> client: who else is online
RELAY = "RELAY"                # client -> server -> other client
RELAY_FAILED = "RELAY_FAILED"  # server -> client: target is gone
BYE = "BYE"

# messages between two clients (inside RELAY, the server just forwards them)
FILE_OFFER = "FILE_OFFER"
FILE_ACCEPT = "FILE_ACCEPT"
FILE_REJECT = "FILE_REJECT"
FILE_START = "FILE_START"
FILE_CHUNK = "FILE_CHUNK"
FILE_END = "FILE_END"
FILE_RESULT = "FILE_RESULT"


# ---------------- framing ----------------
# every message = 4 byte length + data

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise ConnectionError("connection closed by other side")
        data += part
    return data


def send_bytes(sock, data):
    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def recv_bytes(sock):
    header = recv_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    if length > MAX_MESSAGE_SIZE:
        raise ConnectionError("message too big: " + str(length))
    return recv_exact(sock, length)


def send_json(sock, message):
    send_bytes(sock, json.dumps(message).encode("utf-8"))


def recv_json(sock):
    data = recv_bytes(sock)
    try:
        message = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ConnectionError("received invalid JSON")
    if not isinstance(message, dict) or not isinstance(message.get("type"), str):
        raise ConnectionError("received message without type")
    return message


# ---------------- base64 (bytes inside JSON) ----------------

def b64encode(data):
    return base64.b64encode(data).decode("ascii")


def b64decode(text):
    if not isinstance(text, str):
        raise ValueError("expected base64 text")
    return base64.b64decode(text.encode("ascii"), validate=True)


# ---------------- Connection ----------------

class Connection:
    # a real TCP connection (client <-> server)

    def __init__(self, sock, address, hostname, username, os_name, public_key, fingerprint):
        self.sock = sock
        self.address = address
        self.hostname = hostname
        self.username = username
        self.os_name = os_name
        self.public_key = public_key
        self.fingerprint = fingerprint
        self.peer_id = ""
        self.connected_at = time.time()
        self.send_lock = threading.Lock()   # only one thread writes at a time
        self.alive = True
        # statistics (used by the server)
        self.messages_relayed = 0
        self.bytes_relayed = 0
        self.files_offered = 0

    def name(self):
        return self.username + "@" + self.hostname

    def ip(self):
        return self.address[0]

    def send_json(self, message):
        with self.send_lock:
            send_json(self.sock, message)

    def send_json_in_background(self, message):
        # used by receive threads so they never get stuck writing
        t = threading.Thread(target=self._safe_send, args=(message,), daemon=True)
        t.start()

    def _safe_send(self, message):
        try:
            self.send_json(message)
        except OSError:
            pass

    def close(self):
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def __str__(self):
        return self.name() + " (" + self.ip() + ")"


# ---------------- RemotePeer ----------------

class RemotePeer:
    # another client we can reach through the server

    def __init__(self, peer_id, hostname, username, os_name, ip, public_key, fingerprint):
        self.peer_id = peer_id
        self.hostname = hostname
        self.username = username
        self.os_name = os_name
        self.address = (ip, 0)
        self.public_key = public_key
        self.fingerprint = fingerprint
        self.trusted = True
        self.connected_at = time.time()

    def name(self):
        return self.username + "@" + self.hostname

    def ip(self):
        return self.address[0]

    def __str__(self):
        return self.name() + " (" + self.ip() + ")"


# ---------------- helpers ----------------

def format_size(num_bytes):
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return "%.1f %s" % (size, unit)
        size /= 1024
    return "%.1f TB" % size


def format_speed(num_bytes, seconds):
    if seconds <= 0:
        seconds = 0.001
    return format_size(num_bytes / seconds) + "/s"


def format_duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return str(seconds) + "s"
    minutes = seconds // 60
    if minutes < 60:
        return "%dm %ds" % (minutes, seconds % 60)
    return "%dh %dm" % (minutes // 60, minutes % 60)


def get_local_ip():
    # trick: "connect" a UDP socket to find which interface is used (nothing is sent)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()
