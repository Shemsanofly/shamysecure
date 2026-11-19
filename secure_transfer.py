# secure_transfer.py
# ShamySecure - secure file transfer - run in server mode or client mode
#
#   python secure_transfer.py server
#   python secure_transfer.py client --host 192.168.1.10
#
# The server connects the clients together. Clients see each other and send files.
# Files are encrypted with ChaCha20 (new key per file), the key is encrypted with
# RSA-OAEP for the receiver and the file is signed with RSA-PSS by the sender.
# The server only forwards encrypted data, it can NOT read the files.

import os
import sys
import time
import argparse

import network_utils as nu
from secure_core import RelayServer, ClientNode

BANNER = r"""
   ____   _                                ____
  / ___| | |__    __ _  _ __ ___   _   _  / ___|   ___   ___  _   _  _ __   ___
  \___ \ | '_ \  / _` || '_ ` _ \ | | | | \___ \  / _ \ / __|| | | || '__| / _ \
   ___) || | | || (_| || | | | | || |_| |  ___) ||  __/| (__ | |_| || |   |  __/
  |____/ |_| |_| \__,_||_| |_| |_| \__, | |____/  \___| \___| \__,_||_|    \___|
                                   |___/
        ChaCha20 file encryption  +  RSA-2048 key exchange & signatures
"""


# ---------------- input helpers ----------------

current_prompt = ""     # the question we are waiting on right now


def ask(prompt):
    global current_prompt
    current_prompt = prompt
    try:
        return input(prompt).strip()
    except EOFError:
        raise KeyboardInterrupt
    finally:
        current_prompt = ""


def show_notification(text):
    # message from a background thread, then show the question again
    print("\n" + text, flush=True)
    if current_prompt:
        print(current_prompt.lstrip("\n"), end="", flush=True)


def ask_yes_no(prompt):
    while True:
        answer = ask(prompt + " (y/n): ").lower()
        if answer in ["y", "yes"]:
            return True
        if answer in ["n", "no"]:
            return False
        print("Please type y or n")


def ask_number(prompt, minimum, maximum):
    # returns None if the user just presses Enter
    while True:
        answer = ask(prompt)
        if answer == "":
            return None
        if answer.isdigit() and minimum <= int(answer) <= maximum:
            return int(answer)
        print("Please type a number from %d to %d (or Enter to go back)" % (minimum, maximum))


def clean_path(text):
    # remove quotes added by drag & drop and expand ~
    text = text.strip().strip('"').strip("'")
    return os.path.abspath(os.path.expanduser(text))


def pause():
    ask("\nPress Enter to continue...")


# ---------------- printing ----------------

def print_title(title):
    print()
    print("=" * 60)
    print(" " + title)
    print("=" * 60)


def print_my_info(node, mode, port):
    print_title("This computer")
    print(" Mode        :", mode)
    print(" Hostname    :", node.hostname)
    print(" Username    :", node.username)
    print(" OS          :", node.os_name)
    print(" IP address  :", nu.get_local_ip())
    if mode == "server":
        print(" Listening on: port", port)
    else:
        print(" Downloads   :", os.path.abspath(node.downloads_folder))
        if node.is_connected():
            print(" Server      :", node.server, " fingerprint", node.server.fingerprint)
    print(" Keys folder :", os.path.abspath(node.keys_folder))
    print(" Fingerprint :", node.fingerprint)
    print()
    print(" Tell the other person your fingerprint so they can check it.")


def print_computers(computers, server_mode=False):
    if not computers:
        if server_mode:
            print(" No clients connected yet.")
        else:
            print(" No other computers online. Ask someone to connect to the same server.")
        return
    print(" %-3s %-30s %-16s %-20s %-10s %s" % ("#", "User@Host", "IP", "OS", "Online", "Key"))
    print(" " + "-" * 90)
    for i, c in enumerate(computers, start=1):
        online = nu.format_duration(time.time() - c.connected_at)
        if server_mode:
            key = "OK"
        else:
            key = "OK" if c.trusted else "CHANGED!"
        print(" %-3d %-30s %-16s %-20s %-10s %s" % (i, c.name()[:30], c.ip(), c.os_name[:20], online, key))


def print_computer_details(c):
    print(" Name        :", c.name())
    print(" IP          :", c.ip())
    print(" OS          :", c.os_name)
    print(" Fingerprint :", c.fingerprint)
    if hasattr(c, "trusted") and not c.trusted:
        print(" WARNING     : key changed since last time, transfers are blocked")


def progress_bar(percent, width=20):
    filled = int(width * percent / 100)
    return "[" + "#" * filled + "." * (width - filled) + "]"


def print_transfers(transfers):
    if not transfers:
        print(" No transfers yet.")
        return
    print(" %-4s %-30s %-22s %-10s %-27s %s" % ("Dir", "File", "Peer", "Size", "Progress", "Status"))
    print(" " + "-" * 110)
    for t in transfers:
        arrow = "-->" if t.direction == "send" else "<--"
        print(" %-4s %-30s %-22s %-10s %s %3d%%  %s" % (
            arrow, t.filename[:30], t.peer_name[:22], nu.format_size(t.size),
            progress_bar(t.progress()), t.progress(), t.status))
        if t.message and t.is_finished():
            print("      note: " + t.message)


def menu_known_peers(node):
    while True:
        print_title("Trusted computers (known fingerprints)")
        names = sorted(node.known_peers.keys())
        if not names:
            print(" No trusted computers yet.")
            pause()
            return

        for i, name in enumerate(names, start=1):
            entry = node.known_peers[name]
            print(" %d) %-30s %s  (first seen %s)" % (i, name, entry["fingerprint"], entry["first_seen"]))

        print("\n Remove a computer if it made a new key on purpose.")
        number = ask_number(" Number to remove (Enter = back): ", 1, len(names))
        if number is None:
            return
        name = names[number - 1]
        if ask_yes_no(" Really remove " + name + "?"):
            node.forget_peer(name)
            print(" [*] Removed. It will be trusted again on the next connection.")


# =====================================================================
# SERVER MODE
# =====================================================================

def server_show_clients(server):
    print_title("Connected computers")
    clients = server.get_clients()
    print_computers(clients, server_mode=True)
    if not clients:
        pause()
        return
    number = ask_number("\n Show details of number (Enter = back): ", 1, len(clients))
    if number is not None:
        c = clients[number - 1]
        print()
        print_computer_details(c)
        print(" Files sent  :", c.files_offered)
        print(" Data relayed:", nu.format_size(c.bytes_relayed), "(encrypted, server can't read it)")
        pause()


def server_show_activity(server):
    print_title("Relay activity (last %d events)" % len(server.get_activity()))
    events = server.get_activity()
    if not events:
        print(" Nothing happened yet.")
    for line in events:
        print(" " + line)
    print("\n Note: the server sees who sends to who and the file names,")
    print("       but the file content is encrypted with a key only the receiver has.")
    pause()


def server_kick(server):
    print_title("Disconnect a computer")
    clients = server.get_clients()
    print_computers(clients, server_mode=True)
    if not clients:
        pause()
        return
    number = ask_number("\n Number to disconnect (Enter = back): ", 1, len(clients))
    if number is None:
        return
    c = clients[number - 1]
    if ask_yes_no(" Disconnect " + c.name() + "?"):
        server.kick(c)
        print(" [*] Disconnected.")


def server_menu(server, port):
    while True:
        clients = server.get_clients()
        print_title("SERVER MENU  (port %d | %d computers connected)" % (port, len(clients)))
        print(" 1) Show connected computers")
        print(" 2) Relay activity")
        print(" 3) My info / fingerprint")
        print(" 4) Trusted computers")
        print(" 5) Disconnect a computer")
        print(" 0) Stop server")

        choice = ask("\n Choose: ")
        if choice == "1":
            server_show_clients(server)
        elif choice == "2":
            server_show_activity(server)
        elif choice == "3":
            print_my_info(server, "server", port)
            pause()
        elif choice == "4":
            menu_known_peers(server)
        elif choice == "5":
            server_kick(server)
        elif choice == "0":
            if clients and not ask_yes_no(" %d computers are connected, stop anyway?" % len(clients)):
                continue
            return
        elif choice == "":
            continue
        else:
            print(" Unknown option.")


def run_server(args):
    server = RelayServer(args.keys, use_password=args.password, display_name=args.name)
    server.notify = show_notification
    print_my_info(server, "server", args.port)
    try:
        server.start(args.port)
    except OSError as e:
        sys.exit("[!] Could not start server on port %d: %s" % (args.port, e))

    print("\n [*] Server is running. Clients can connect with:")
    print("     python secure_transfer.py client --host %s --port %d" % (nu.get_local_ip(), args.port))

    try:
        server_menu(server, args.port)
    except KeyboardInterrupt:
        print()
    print(" [*] Stopping server...")
    server.shutdown()
    print(" [*] Bye!")


# =====================================================================
# CLIENT MODE
# =====================================================================

def choose_computer(client):
    peers = client.get_peers()
    if not peers:
        print(" No other computers online.")
        return None
    print_computers(peers)
    number = ask_number("\n Choose computer number (Enter = back): ", 1, len(peers))
    if number is None:
        return None
    peer = peers[number - 1]
    if not peer.trusted:
        print(" [!] The key of %s changed, transfers are blocked." % peer.name())
        print("     Check with them, then remove them in 'Trusted computers' if it is OK.")
        return None
    return peer


def check_file(path):
    if not os.path.exists(path):
        print(" [!] File does not exist:", path)
        return False
    if not os.path.isfile(path):
        print(" [!] Not a file:", path)
        return False
    if not os.access(path, os.R_OK):
        print(" [!] No permission to read:", path)
        return False
    return True


def client_show_peers(client):
    print_title("Online computers")
    peers = client.get_peers()
    print_computers(peers)
    if peers:
        number = ask_number("\n Show details of number (Enter = back): ", 1, len(peers))
        if number is not None:
            print()
            print_computer_details(peers[number - 1])
            pause()
    else:
        pause()


def client_send_file(client):
    print_title("Send a file")
    peer = choose_computer(client)
    if peer is None:
        pause()
        return

    path = clean_path(ask(" Path of the file to send: "))
    if not check_file(path):
        pause()
        return

    size = os.path.getsize(path)
    print(" Sending '%s' (%s) to %s" % (os.path.basename(path), nu.format_size(size), peer.name()))
    if not ask_yes_no(" Continue?"):
        return

    client.send_file(peer, path)
    print(" [*] Request sent. The transfer runs in the background.")
    print("     You will get a message when it is done. See 'Transfers' for progress.")


def client_send_folder(client):
    print_title("Send all files in a folder")
    peer = choose_computer(client)
    if peer is None:
        pause()
        return

    folder = clean_path(ask(" Path of the folder: "))
    if not os.path.isdir(folder):
        print(" [!] Not a folder:", folder)
        pause()
        return

    files = []
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if os.path.isfile(path) and os.access(path, os.R_OK):
            files.append(path)

    if not files:
        print(" [!] No readable files in this folder (sub folders are skipped)")
        pause()
        return

    total = sum(os.path.getsize(p) for p in files)
    print(" Found %d files, total %s" % (len(files), nu.format_size(total)))
    for p in files:
        print("   -", os.path.basename(p))
    if not ask_yes_no(" Send all of them to " + peer.name() + "?"):
        return

    for p in files:
        client.send_file(peer, p)
    print(" [*] %d requests sent, every file gets its own key." % len(files))


def client_incoming(client):
    print_title("Incoming file requests")
    offers = client.get_incoming_offers()
    if not offers:
        print(" No requests waiting.")
        pause()
        return

    for i, t in enumerate(offers, start=1):
        print(" %d) '%s' (%s) from %s" % (i, t.filename, nu.format_size(t.size), t.peer_name))

    number = ask_number("\n Choose request number (Enter = back): ", 1, len(offers))
    if number is None:
        return
    t = offers[number - 1]

    print("\n File   :", t.filename)
    print(" Size   :", nu.format_size(t.size))
    print(" From   :", t.peer_name)
    print(" Key    :", t.peer.fingerprint)
    if t.wire_name != t.filename:
        print(" Note   : original name was changed for safety")

    if ask_yes_no(" Accept this file?"):
        client.accept_offer(t)
        print(" [*] Accepted, receiving in the background...")
    else:
        client.reject_offer(t)
        print(" [*] Rejected.")


def client_transfers(client):
    while True:
        print_title("Transfers")
        print_transfers(client.get_transfers())
        print()
        print(" r) refresh   c) clear finished   Enter) back")
        choice = ask(" > ").lower()
        if choice == "r":
            continue
        if choice == "c":
            client.clear_finished_transfers()
            continue
        return


def client_settings(client):
    while True:
        print_title("Settings")
        print(" 1) Auto-accept incoming files : " + ("ON" if client.auto_accept else "OFF"))
        print(" 2) Downloads folder           : " + os.path.abspath(client.downloads_folder))
        print(" Enter) back")
        choice = ask(" > ")
        if choice == "1":
            client.auto_accept = not client.auto_accept
            if client.auto_accept:
                print(" [!] Careful: anyone online can now drop files on your computer.")
        elif choice == "2":
            folder = clean_path(ask(" New downloads folder: "))
            try:
                os.makedirs(folder, exist_ok=True)
                client.downloads_folder = folder
                print(" [*] Downloads folder changed.")
            except OSError as e:
                print(" [!] Could not use that folder:", e)
        else:
            return


def try_connect(client, host, port):
    print(" [*] Connecting to server %s:%d ..." % (host, port))
    try:
        client.connect(host, port)
        time.sleep(0.3)     # give the server a moment to send the list
        return True
    except (OSError, ConnectionError, ValueError) as e:
        print(" [!] Could not connect:", e)
        return False


def client_menu(client, host, port):
    while True:
        offers = len(client.get_incoming_offers())
        peers = len(client.get_peers())
        active = len([t for t in client.get_transfers() if not t.is_finished()])
        server_text = "connected" if client.is_connected() else "NOT connected"

        print_title("MAIN MENU  (server %s | %d computers online | %d active transfers)"
                    % (server_text, peers, active))
        print(" 1) Show online computers")
        print(" 2) Send a file")
        print(" 3) Send all files in a folder")
        print(" 4) Incoming file requests" + ("  <-- %d waiting!" % offers if offers else ""))
        print(" 5) Transfers")
        print(" 6) My info / fingerprint")
        print(" 7) Trusted computers")
        print(" 8) Settings")
        if client.is_connected():
            print(" 9) Disconnect from server")
        else:
            print(" 9) Reconnect to server")
        print(" 0) Quit")

        pending = client.get_incoming_offers()
        if pending:
            first = pending[0]
            print("\n [?] '%s' (%s) from %s is waiting:  Enter = accept,  n = reject" % (
                first.filename, nu.format_size(first.size), first.peer_name))

        choice = ask("\n Choose: ")

        # Enter / n answer the oldest waiting file request (it may have arrived while we waited)
        pending = client.get_incoming_offers()
        if choice == "" and pending:
            client.accept_offer(pending[0])
            print(" [*] Accepted '%s', receiving in the background..." % pending[0].filename)
        elif choice.lower() == "n" and pending:
            client.reject_offer(pending[0])
            print(" [*] Rejected '%s'." % pending[0].filename)
        elif choice == "1":
            client_show_peers(client)
        elif choice == "2":
            client_send_file(client)
        elif choice == "3":
            client_send_folder(client)
        elif choice == "4":
            client_incoming(client)
        elif choice == "5":
            client_transfers(client)
        elif choice == "6":
            print_my_info(client, "client", port)
            pause()
        elif choice == "7":
            menu_known_peers(client)
        elif choice == "8":
            client_settings(client)
        elif choice == "9":
            if client.is_connected():
                if ask_yes_no(" Disconnect from server?"):
                    client.disconnect()
            else:
                try_connect(client, host, port)
        elif choice == "0":
            active = [t for t in client.get_transfers() if not t.is_finished()]
            if active and not ask_yes_no(" %d transfers still running, quit anyway?" % len(active)):
                continue
            return
        elif choice == "":
            continue
        else:
            print(" Unknown option.")


def run_client(args):
    client = ClientNode(
        keys_folder=args.keys,
        downloads_folder=args.downloads,
        auto_accept=args.auto_accept,
        use_password=args.password,
        display_name=args.name,
    )
    client.notify = show_notification
    print_my_info(client, "client", args.port)

    if not try_connect(client, args.host, args.port):
        print(" [*] You can try again with option 9 in the menu.")

    try:
        client_menu(client, args.host, args.port)
    except KeyboardInterrupt:
        print()
    print(" [*] Closing connection...")
    client.shutdown()
    print(" [*] Bye!")


# =====================================================================
# start up
# =====================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="ShamySecure - secure file transfer with ChaCha20 + RSA",
        epilog="example: python secure_transfer.py client --host 192.168.1.10",
    )
    parser.add_argument("mode", choices=["server", "client"], help="run as server or client")
    parser.add_argument("--host", default="127.0.0.1", help="server IP (client mode)")
    parser.add_argument("--port", type=int, default=nu.DEFAULT_PORT, help="TCP port (default %d)" % nu.DEFAULT_PORT)
    parser.add_argument("--keys", default="keys", help="folder for RSA keys (default: keys)")
    parser.add_argument("--downloads", default="received", help="folder for received files (client)")
    parser.add_argument("--auto-accept", action="store_true", help="accept incoming files without asking")
    parser.add_argument("--password", action="store_true", help="protect a NEW private key with a password")
    parser.add_argument("--name", help="show this name instead of the hostname (for demos on one PC)")
    return parser.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    if not (1 <= args.port <= 65535):
        sys.exit("[!] Port must be between 1 and 65535")

    if args.mode == "server":
        run_server(args)
    else:
        run_client(args)


if __name__ == "__main__":
    main()
