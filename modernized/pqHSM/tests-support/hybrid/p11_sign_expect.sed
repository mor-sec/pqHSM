# Harness step 4m: the rows of p11_sign.c's output that differ from C by a recorded DIV.
# Applied to C's output; the result must equal the hybrid's exactly.
#
# DIV-050: logged out or as SO, a secret or private key, token or session, is out of sight at
# SignInit and VerifyInit (0x60), and the logout ends every operation under way on one (0x91; the
# length is left as the caller set it). A verification with a public key goes on.
s/^life signupdate after logout\t0\t/life signupdate after logout\t0x91\t/
s/^\(life signfinal\( ed\)\? after logout\)\t0\t0x[0-9a-f]*\t/\1\t0x91\t0x11170\t/
s/^life verify session key after logout\t0xc0\t/life verify session key after logout\t0x91\t/
s/^\(life \(so \)\?signinit\( ed\| session key\| token key\)\?\( logged out\)\?\)\t0x\?[09]*\t/\1\t0x60\t/
s/^\(life \(so \)\?verifyinit session key\( logged out\)\?\)\t0\t/\1\t0x60\t/
s/^\(life \(so \)\?\(sign\|verify\) session key\( logged out\)\?\)\t0x\?[0c]*\t/\1\t0x91\t/
# ... and what follows from it: the refused C_Sign no longer overwrites the Ed25519 signature
# the public key then verifies, and the SO's refused SignInit leaves no operation active.
s/^life verify public key logged out\t0xc0\t/life verify public key logged out\t0\t/
s/^life signinit before fork\t0x90\t/life signinit before fork\t0\t/
# DIV-062: each SignInit starts a fresh MAC stream, so the one the ALWAYS_AUTH updates left is not
# continued: the signature verifies.
s/^life verify needs no context login\t0xc0\t/life verify needs no context login\t0\t/
# DIV-051: a forked child that has not called C_Initialize, and every call after C_Finalize,
# is 0x190.
s/^child signfinal\t0$/child signfinal\t0x190/
s/^\(life \(sign\|signinit\|verifyfinal\) finalized\)\t0x[0-9a-f]*\t/\1\t0x190\t/
