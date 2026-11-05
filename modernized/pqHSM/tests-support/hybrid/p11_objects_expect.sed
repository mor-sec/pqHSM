# Harness step 4i: the rows of p11_objects.c's output that differ from C by a recorded DIV.
# Applied to C's output; the result must equal the hybrid's exactly.
#
# DIV-050: the SO cannot destroy the user's key, so the find after it sees it.
s/^so destroy key\t0\t0\t-$/so destroy key\t0x82\t0\t-/
s/^find after destroys found\t0\t0x2\t3,5$/find after destroys found\t0\t0x3\t4,5,3/
# RULE-092: an unknown handle on destroy is 0x82.
s/^destroy \(token again\|bad handle\|handle 0\)\t0x60\t/destroy \1\t0x82\t/
# DIV-060: a copy asked to be uncopyable stays so.
s/^copy made uncopyable attr 0x171\t0\t0x1\t01$/copy made uncopyable attr 0x171\t0\t0x1\t00/
# DIV-056: copies of the CKA_SIGN=FALSE source keep SIGN FALSE and its mechanism list.
/^copy dated /!s/^\(copy [^\t]* attr 0x108\)\t0\t0x1\t01$/\1\t0\t0x1\t00/
s/^\(copy [^\t]* attr 0x40000600\)\t0\t0\t-$/\1\t0\t0x8\t8110000000000000/
# DIV-056: a copy template may only narrow; nested templates are 0xD1; a malformed list 0x13;
# an inherited token copy needs a read-write session.
s/^copy sign true\t0x12\t/copy sign true\t0x10\t/
s/^copy wider mechs\t0x12\t/copy wider mechs\t0x10\t/
s/^copy mechs odd length\t0x12\t/copy mechs odd length\t0x13\t/
s/^copy \(wrap template\|wrap template unsupported\|unwrap template 5\|derive template\)\t0x12\t/copy \1\t0xd1\t/
s/^copy ro token inherited\t0\t/copy ro token inherited\t0xb5\t/
# DIV-056: ENCRYPT TRUE to FALSE is a narrowing, so this copy is made (one more handle for
# every later copy).
s/^copy extractable false\t0\t0x6\t/copy extractable false\t0\t0x7\t/
s/^copy id\t0\t0x7\t/copy id\t0\t0x8\t/
s/^copy unmodifiable undestroyable\t0\t0x8\t/copy unmodifiable undestroyable\t0\t0x9\t/
s/^copy made uncopyable\t0\t0x9\t/copy made uncopyable\t0\t0xa\t/
s/^copy dated plain\t0\t0xa\t/copy dated plain\t0\t0xb\t/
/^copy encrypt false\t0x12\t0xaaaa\t-$/c\
copy encrypt false\t0\t0x6\t-\
copy encrypt false attr 0x1\t0\t0x1\t01\
copy encrypt false attr 0x3\t0\t0x3\t737263\
copy encrypt false attr 0x10\t0\t0\t-\
copy encrypt false attr 0x86\t0\t0x1\t00\
copy encrypt false attr 0x102\t0\t0\t-\
copy encrypt false attr 0x103\t0\t0x1\t01\
copy encrypt false attr 0x104\t0\t0x1\t00\
copy encrypt false attr 0x108\t0\t0x1\t00\
copy encrypt false attr 0x110\t0\t0\t-\
copy encrypt false attr 0x111\t0\t0\t-\
copy encrypt false attr 0x162\t0\t0x1\t00\
copy encrypt false attr 0x170\t0\t0x1\t01\
copy encrypt false attr 0x171\t0\t0x1\t01\
copy encrypt false attr 0x172\t0\t0x1\t01\
copy encrypt false attr 0x634\t0\t0xffffffffffffffff\t-\
copy encrypt false attr 0x40000600\t0\t0x8\t8110000000000000
