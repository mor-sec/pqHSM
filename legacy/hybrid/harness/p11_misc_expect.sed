# p11_misc.c (harness step 4o): the C rows the hybrid prints differently by a recorded
# divergence. Exact rows only.
# RULE-014: in the strict build CKM_GENERIC_SECRET_KEY_GEN advertises 14 bytes at least (p11/src/ffi/misc.rs;
# step 4p's all-mechanisms run drops this rule). The counts below are any profile's.
s/^info 0x350\t0\t0x350\t1,40,8000$/info 0x350\t0\t0x350\te,40,8000/
# DIV-051: after C_Finalize every call is 0x190 and writes nothing.
s/^finalized list slot 1\t0\t0x[0-9a-f]*\t-$/finalized list slot 1\t0x190\t0xaaaa\t-/
s/^finalized list no count\t0x7\t0\t-$/finalized list no count\t0x190\t0\t-/
s/^finalized list size\t0\t0x[0-9a-f]*\t-$/finalized list size\t0x190\t0xaaaa\t-/
s/^finalized list short\t0x150\t0x[0-9a-f]*\taaaaaaaaaaaaaaaa$/finalized list short\t0x190\t0xaaa9\taaaaaaaaaaaaaaaa/
s/^finalized list get\t0\t0x[0-9a-f]*\t.*$/finalized list get\t0x190\t0x400\t-/
s/^finalized info\t0\t0x250\t0,0,400$/finalized info\t0x190\t0x250\t-/
s/^\(random\|seed\|status\|cancel\) finalized\t0xb3\t0\t-$/\1 finalized\t0x190\t0\t-/
s/^wait finalized\t0x8\t0\t-$/wait finalized\t0x190\t0\t-/
# DIV-053: in ERROR, status and cancel are 0x6 (C checked only the session).
s/^error \(status\|cancel\)\t0xb3\t0\t-$/error \1\t0x6\t0\t-/
