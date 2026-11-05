# Harness step 4l: the rows of p11_crypt.c's output that differ from C by a recorded DIV.
# Applied to C's output; the result must equal the hybrid's exactly.
#
# DIV-050: a secret or private key is the user's alone. Logged out or as SO, Init refuses it
# (0x60) whether it is a token or a session key, so the operation's rows go; and C_Logout ends
# the operations under way on one (0x91), the buffer untouched.
s/^\(encrypt\|decrypt\|encupdate\) after logout\t0\t0x10\t[0-9a-f]*$/\1 after logout\t0x91\t0x400\t-/
s/^encfinal after logout\t0\t/encfinal after logout\t0x91\t/
/^\(logged out\|so\) \(token\|session\|not private\) \(enc\|dec\)\( tampered\)\? \(size\|1\|get\|after\)\t/d
/^\(logged out\|so\) \(token\|session\|not private\) dec tampered init\t/d
s/^\(\(logged out\|so\) \(token\|session\|not private\) \(enc\|dec\) init\)\t0\t/\1\t0x60\t/
s/^\(\(logged out\|so\) \(token\|session\|not private\) round trip\)\t1$/\1\t0/
# DIV-051: after C_Finalize every call is 0x190.
s/^encrypt finalized\t0x91\t/encrypt finalized\t0x190\t/
# DIV-061: a single-part AES block mode refuses a key that is not 16, 24 or 32 bytes.
s/^\(\(enc\|dec\) key 20 bytes, use\)\t0\t/\1\t0x62\t/
# DIV-062: an Init after an error starts a fresh context, so the other key's CBC is used.
s/^\(enc update cbc, the other key\t0\t0x10\t\).*/\184f474f35a3090a82aae847eff728ab2/
s/^\(dec update cbc, the other key\t0\t0x10\t\).*/\190992982bef5fd54cae47761b4130adb/
