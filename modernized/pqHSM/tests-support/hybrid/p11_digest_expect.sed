# Harness step 4k: the rows of p11_digest.c's output that differ from C by a recorded DIV.
# Applied to C's output; the result must equal the hybrid's exactly.
#
# DIV-050: logged out, a secret key is out of sight (0x60), so nothing is digested.
s/^logged out key \(aes\|public\)\t0\t0\t-$/logged out key \1\t0x60\t0\t-/
s/^logged out key sensitive\t0x67\t0\t-$/logged out key sensitive\t0x60\t0\t-/
s/^\(logged out key \(aes\|public\) final get\t0\t0x20\t\)be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991$/\1e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/
# DIV-051: after C_Finalize every call is 0x190.
s/^final finalized\t0x91\t/final finalized\t0x190\t/
