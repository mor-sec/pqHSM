"""DIV-072: a tool run without FHSM_PIN at a terminal asks for the PIN there, without echo.

    pin_prompt.py PIN COMMAND...     (FHSM_PIN is removed from COMMAND's environment)

Runs COMMAND on a pseudo-terminal, answers the first "PIN: " it prints with PIN, and prints
one line: whether it was asked, whether the PIN came back on the terminal, its exit status.
"""
import os
import pty
import sys

pin = sys.argv[1].encode()
cmd = sys.argv[2:]
env = {k: v for k, v in os.environ.items() if k != "FHSM_PIN"}
pid, fd = pty.fork()
if pid == 0:
    os.execvpe(cmd[0], cmd, env)
seen, asked = b"", False
while True:
    try:
        b = os.read(fd, 4096)
    except OSError:  # EIO: the child closed the terminal
        break
    if not b:
        break
    seen += b
    if not asked and b"PIN: " in seen:
        os.write(fd, pin + b"\n")
        asked = True
_, status = os.waitpid(pid, 0)
print(
    "asked" if asked else "not asked",
    "PIN echoed" if pin in seen else "PIN not echoed",
    f"rc={os.waitstatus_to_exitcode(status)}",
    sep=", ",
)
