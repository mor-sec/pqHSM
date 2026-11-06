# Harness step 4n: the rows of p11_keys.c's output that differ from C by a recorded DIV.
# Applied to C's output; the result must equal the hybrid's exactly.
#
# DIV-050 (logout half): a logout reloads the token from its file, so the next handle is the
# file's, past the live session objects', not C's running count; the session objects the
# closed sessions destroyed give their handles up.
s/^so key\t0\t0x5\t/so key\t0\t0x1\t/
s/^so pair\t0\t0x6,0x7\t/so pair\t0\t0x2,0x3\t/
s/^token key\t0\t0x8\t/token key\t0\t0x4\t/
# DIV-051: a forked child that has not called C_Initialize, and every call after C_Finalize,
# is 0x190.
s/^\(child \(key\|pair\)\)\t0\t/\1\t0x190\t/
s/^\(\(key\|pair\) finalized\)\t0xb3\t/\1\t0x190\t/
