# Harness step 4m: the rows of p11_sign.c's output that differ from C by a recorded DIV.
# Applied to C's output; the result must equal the hybrid's exactly.
#
# DIV-050: logged out or as SO, a private or secret token key is out of sight (0x60). Interim,
# with C_Sign* still C's over Rust's object access: an operation under way is not yet ended by
# the logout, but its key is refused at Final; the session key stays usable. Slice 5b changes
# these rows again (Init refuses, logout ends the operation: 0x91).
s/^life signfinal ed after logout\t0\t0x40\t-$/life signfinal ed after logout\t0x60\t0x11170\t-/
s/^life verify public after logout\t0\t/life verify public after logout\t0xc0\t/
s/^\(life signinit\( ed\)\? logged out\)\t0\t/\1\t0x60\t/
s/^\(life \(so \)\?signinit session key\( logged out\)\?\)\t0x90\t/\1\t0\t/
s/^life so verify session key\t0xc0\t/life so verify session key\t0\t/
# DIV-051: a forked child that has not called C_Initialize, and every call after C_Finalize,
# is 0x190.
s/^child signfinal\t0$/child signfinal\t0x190/
s/^\(life \(sign\|signinit\|verifyfinal\) finalized\)\t0x[0-9a-f]*\t/\1\t0x190\t/
