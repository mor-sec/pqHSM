# Harness step 4l: the rows of p11_crypt.c's output that differ from C by a recorded DIV.
# Applied to C's output; the result must equal the hybrid's exactly.
#
# DIV-050: logout drops the token's keys, so an operation under way on one, and every new
# one, finds no key (0x60). A session key stays (SEC-001's M1 gap, slice 4 closes it).
s/^encrypt after logout\t0\t0x10\tf7021c01de43c8147cd2477a7eba55b3$/encrypt after logout\t0x60\t0x400\t-/
/^logged out \(token\|not private\) \(enc\|dec\)\( tampered\)\? \(size\|1\|get\|after\)\t/d
/^logged out \(token\|not private\) dec tampered init\t/d
s/^\(logged out \(token\|not private\) \(enc\|dec\) init\)\t0\t/\1\t0x60\t/
s/^\(logged out \(token\|not private\) round trip\)\t1$/\1\t0/
# DIV-051: after C_Finalize every call is 0x190.
s/^encrypt finalized\t0x91\t/encrypt finalized\t0x190\t/
