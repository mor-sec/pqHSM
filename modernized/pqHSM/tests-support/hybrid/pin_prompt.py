"""DIV-072: a tool run without FHSM_PIN at a terminal asks for the PIN there, without echo.

    pin_prompt.py PIN COMMAND...     (FHSM_PIN is removed from COMMAND's environment)

Runs COMMAND on a pseudo-terminal, answers every "PIN: " it prints with PIN, and prints one
line: whether it was asked (and how often, past once), whether the PIN came back on the
terminal, its exit status.
"""
import os
import pty
import signal
import sys

pin = sys.argv[1].encode()
cmd = sys.argv[2:]
env = {k: v for k, v in os.environ.items() if k not in ("FHSM_PIN", "PQHSM_PIN")}
pid, fd = pty.fork()
if pid == 0:
    os.execvpe(cmd[0], cmd, env)
signal.alarm(30)  # a prompt this does not recognise would otherwise wait for input forever
seen, asked = b"", 0
while True:
    try:
        b = os.read(fd, 4096)
    except OSError:  # EIO: the child closed the terminal
        break
    if not b:
        break
    seen += b
    if seen.count(b"PIN: ") > asked:
        os.write(fd, pin + b"\n")
        asked += 1
_, status = os.waitpid(pid, 0)
print(
    {0: "not asked", 1: "asked"}.get(asked, f"asked {asked} times"),
    "PIN echoed" if pin in seen else "PIN not echoed",
    f"rc={os.waitstatus_to_exitcode(status)}",
    sep=", ",
)
