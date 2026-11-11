"""One raw HTTP exchange over a Unix socket, for service_transcripts.sh.

    python3 -I service_client.py SOCKET OUT MODE < request-bytes

MODE send: send stdin, half-close, read to EOF. hold: send stdin, keep the connection open,
read to EOF (a body that never finishes). silent: connect, send nothing, read to EOF
(the acceptor's first-byte deadline). hangup: connect and close. The response bytes go to OUT
(empty when none came). Exit 0 always; a failure is written to OUT as "NO RESPONSE (...)".
"""
import socket, sys

path, out, mode = sys.argv[1], sys.argv[2], sys.argv[3]
data = sys.stdin.buffer.read() if mode in ("send", "hold") else b""
got = b""
s = socket.socket(socket.AF_UNIX)
s.settimeout(15)
try:
    s.connect(path)
    if mode != "hangup":
        s.sendall(data)
        if mode == "send":
            s.shutdown(socket.SHUT_WR)
        while True:
            b = s.recv(65536)
            if not b:
                break
            got += b
except Exception as e:  # the transcript records it rather than stopping
    got += f"NO RESPONSE ({type(e).__name__})".encode()
finally:
    s.close()
open(out, "wb").write(got)
