#!/usr/bin/env python3
"""atlas-core -- a stand-in for the Aldercrest archive service.

    python3 atlascore.py [port]

Listens on 127.0.0.1 and nowhere else. Reads one file, answers questions,
exits. No outbound connections, nothing written to disk.

--

The real atlas-core ran on a machine I no longer have. The client refuses to
start without it, so I rebuilt the protocol by watching what the client sent.
It is not complete. It is what VESTIBULE needs in order to agree to run, and
nothing beyond that.

I never got the later revisions to talk to me. They send a different HELO and
expect something back that I could not work out. The earlier ones connect
perfectly well -- they simply cannot display half of what the service hands
them, which on reflection probably suited everybody.

-- dyloo35
"""

import hmac
import json
import os
import socketserver
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypt import account_hash, derive, unseal

ARCHIVE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "archive.dat")

# The last revision I managed to reproduce. Above it the HELO changes and I
# never found what it wanted back.
MAX_REVISION = (12, 2)

# These two are findings, not decisions. The server only returned the subject
# table from 12.0, and the classification column only from 12.2. An older
# client connects perfectly well and simply cannot see that anything is
# missing.
MIN_SUBJECTS = (12, 0)
MIN_DANGER = (12, 2)

# The server checked the account before it would even ask for the keys, and
# refused an unknown name outright. I do not have the account table. I have
# mine, and not in the clear: this file is public, and my user name is the
# first thing they would look for. So the name and the password are hashed
# separately, and the service can say "no such account" without anyone reading
# out of here which account does exist.
#
# This gate protects nothing serious and I know it. It only gives the client
# back the behaviour it expects. You did not get into Aldercrest by typing
# whatever came to mind.
# -- dyloo35
ACCOUNTS = {
    "2f6cc0a596c01de788f3bf6540c61768fdb9f358412fef13aee19dd792f06847":
        "7f497639cbca84b0cb04b1f3e428420e8790a73a476c85659b99b9e03698b122",
}

_lock = threading.Lock()
_cache = {}


def parse_rev(s):
    try:
        a, b = s.split(".")
        return (int(a), int(b))
    except Exception:
        return None


def load(creds):
    """Decrypt the archive. Cached -- scrypt on every request, no."""
    with _lock:
        if creds in _cache:
            return _cache[creds]
        data = json.loads(unseal(open(ARCHIVE, "rb").read(), derive(*creds)))
        _cache[creds] = data
        return data


class Handler(socketserver.StreamRequestHandler):
    timeout = 300

    def send(self, line):
        self.wfile.write((line + "\r\n").encode("utf-8", "replace"))

    def handle(self):
        rev = None
        data = None
        self.send("220 ATLAS-CORE")
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            parts = raw.decode("utf-8", "replace").strip().split()
            if not parts:
                continue
            cmd = parts[0].upper()

            if cmd == "QUIT":
                self.send("221 CLOSING")
                return

            if cmd == "HELO":
                if len(parts) != 2 or "/" not in parts[1]:
                    self.send("501 SYNTAX")
                    continue
                product, _, rs = parts[1].partition("/")
                r = parse_rev(rs)
                if product.upper() != "VESTIBULE" or r is None:
                    self.send("501 SYNTAX")
                    continue
                if r > MAX_REVISION:
                    # Deliberately silent about which revision it wants.
                    self.send("505 PROTOCOL REVISION NOT SUPPORTED")
                    rev = None
                    continue
                rev = r
                self.send("250 HELLO")
                continue

            if rev is None:
                self.send("503 HELO FIRST")
                continue

            if cmd == "LOGIN":
                if len(parts) != 3:
                    self.send("501 SYNTAX")
                    continue
                who = ACCOUNTS.get(account_hash(parts[1]))
                if who is None:
                    self.send("531 NO SUCH ACCOUNT")
                    continue
                if not hmac.compare_digest(
                        who, account_hash(parts[1], parts[2])):
                    self.send("535 AUTHENTICATION FAILED")
                    continue
                self.send("250 ACCOUNT OK")
                continue

            # AUTH does not require a prior LOGIN. It stands on its own, since
            # the archive only decrypts with all six fields correct. The client
            # opens one connection per request and does not reattach to an
            # account -- it hands over the six every time.
            if cmd == "AUTH":
                if len(parts) != 7:
                    self.send("501 SYNTAX")
                    continue
                try:
                    data = load(tuple(parts[1:]))
                except Exception:
                    data = None
                    self.send("535 REJECTED")
                    continue
                self.send("235 AUTHENTICATED")
                continue

            if data is None:
                self.send("530 AUTH REQUIRED")
                continue

            if cmd == "LIST":
                self.do_list(parts, rev, data)
            elif cmd == "GET":
                self.do_get(parts, rev, data)
            else:
                self.send("500 UNKNOWN COMMAND")

    def do_list(self, parts, rev, data):
        if len(parts) < 2:
            self.send("501 SYNTAX")
            return
        what = parts[1].upper()
        off = int(parts[2]) if len(parts) > 2 else 0
        cnt = int(parts[3]) if len(parts) > 3 else 50

        if what == "CLAIMS":
            rows = data["claims"]
            keys = ["ref", "name", "policy", "type", "opened", "status", "amount"]
        elif what == "SUBJECTS":
            if rev < MIN_SUBJECTS:
                self.send("502 NOT IMPLEMENTED")
                return
            rows = data["subjects"]
            keys = ["id", "name", "dob", "policy", "cost", "reviewed"]
            if rev >= MIN_DANGER:
                keys.insert(5, "danger")
        else:
            self.send("501 SYNTAX")
            return

        page = rows[off:off + cnt]
        self.send("250 %d %d" % (len(page), len(rows)))
        self.send("\t".join(keys))
        for row in page:
            self.send("\t".join(str(row.get(k, "")) for k in keys))
        self.send(".")

    def do_get(self, parts, rev, data):
        if len(parts) != 2:
            self.send("501 SYNTAX")
            return
        ref = parts[1]
        for row in data["claims"] + data["subjects"]:
            if row.get("ref") == ref or row.get("id") == ref:
                if "danger" in row and rev < MIN_DANGER:
                    row = {k: v for k, v in row.items() if k != "danger"}
                self.send("250 RECORD")
                for k, v in sorted(row.items()):
                    self.send("%s\t%s" % (k, v))
                self.send(".")
                return
        self.send("404 NO SUCH RECORD")


def listen(factory, port, label):
    """Bind, or explain. Never a traceback: a busy port is the most ordinary
    failure there is, and a Python trace would read as a broken program when
    in fact it is already running."""
    try:
        return factory()
    except OSError as e:
        if getattr(e, "errno", None) not in (98, 48, 10048):
            raise
        sys.stderr.write(
            "\n%s: port %d is already in use.\n\n"
            "  Another instance is probably already running. Use that one,\n"
            "  stop it, or start this one on a different port:\n\n"
            "      python3 %s %d\n\n"
            % (label, port, os.path.basename(sys.argv[0]), port + 1))
        raise SystemExit(2)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7042
    if not os.path.exists(ARCHIVE):
        sys.exit("atlascore: archive.dat introuvable")
    srv = listen(lambda: Server(("127.0.0.1", port), Handler),
                 port, "atlascore")
    print("atlas-core sur 127.0.0.1:%d" % port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print()
