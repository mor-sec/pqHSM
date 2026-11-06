# Harness step 4n: the rows of p11_keys.c's output that differ from C by a recorded DIV.
# Applied to C's output; the result must equal the hybrid's exactly.
#
# DIV-050 (logout half): a logout reloads the token from its file, so the next handle is the
# file's, past the live session objects', not C's running count; the session objects the
# closed sessions destroyed give their handles up.
s/^so key\t0\t0x5\t/so key\t0\t0x1\t/
s/^so pair\t0\t0x6,0x7\t/so pair\t0\t0x2,0x3\t/
s/^token key\t0\t+4\t/token key\t0\t+0\t/
# DIV-051: a forked child that has not called C_Initialize, and every call after C_Finalize,
# is 0x190.
s/^\(child \(key\|pair\)\)\t0\t/\1\t0x190\t/
s/^\(\(key\|pair\) finalized\)\t0xb3\t/\1\t0x190\t/
#
# A key C stored that Rust refuses: its dump goes, the call is the refusal, nothing stored.
# RULE-014 (strict build): a generic secret under 112 bits is 0x62.
/^generic 1[3]\? [A-Z_]*\t/d
s/^\(generic 1[3]\?\)\t0\t+1\t-$/\1\t0x62\t-\t-\n\1 objects\t0\t+0\t-/
# DIV-064: a PBKDF2 AES key is 16, 24 or 32 bytes.
/^pbkdf2 aes type of 5 [A-Z_]*\t/d
s/^\(pbkdf2 aes type of 5\)\t0\t+1\t-$/\1\t0x62\t-\t-\n\1 objects\t0\t+0\t-/
# RULE-006: an iteration count past 32 bits is 0x71 (C ran it modulo 2^32).
/^pbkdf2 2^32+1000 iterations [A-Z_]*\t/d
s/^\(pbkdf2 2^32+1000 iterations\)\t0\t+1\t-$/\1\t0x71\t-\t-\n\1 objects\t0\t+0\t-/
# RULE-015: e must exceed 2^16 (e = 3 is 0x13), and the key is made with the e asked for (C
# used 65537).
/^rsa e 3 \(pub\|priv\) [A-Z_]*\t/d
s/^\(rsa e 3\)\t0\t+1,+1\t-$/\1\t0x13\t-,-\t-\n\1 objects\t0\t+0\t-/
s/^\(rsa e 2^17+1 \(pub\|priv\) PUBLIC_EXPONENT\t0\t0x3\t\)010001$/\1020001/
# RULE-017: a parameter set of another family is 0x13 before any key is made. C made one:
# a pairwise failure (0x6) when the family's check did not fit it, else a key of the wrong
# family stored under this one's type.
s/^\(\(mlkem\|mldsa\|slhdsa\) name '[^']*'\)\t0x6\t-,-\t-$/\1\t0x13\t-,-\t-/
/^\(mldsa name 'SLH-DSA-SHAKE-128f'\|slhdsa name 'ML-DSA-44'\) \(pub\|priv\) [A-Z_]*\t/d
s/^\(mldsa name 'SLH-DSA-SHAKE-128f'\|slhdsa name 'ML-DSA-44'\)\t0\t+1,+1\t-$/\1\t0x13\t-,-\t-\n\1 objects\t0\t+0\t-/
# DIV-065 (scenario 3): an imported RSA key is checked. An empty modulus fails the public
# check and another key's d the pairwise check (0x13, C stored both); without the CRT five the
# template is incomplete (0xD0; C failed encoding it, 0x6).
/^\(rsa pub empty modulus\|rsa priv another key's d\) [A-Z_]*\t/d
s/^\(rsa pub empty modulus\|rsa priv another key's d\)\t0\t+1\t-$/\1\t0x13\t-\t-\n\1 objects\t0\t+0\t-/
s/^\(rsa priv n e d\)\t0x6\t/\1\t0xd0\t/
# DIV-066 (scenario 3): a rebuilt public key keeps CKA_ENCAPSULATE FALSE (C's rebuilt-key path
# never applied the encapsulation flags).
s/^\(mlkem512 pub encapsulate false ENCAPSULATE\t0\t0x1\t\)01$/\100/
# RULE-059 (slices 6b and 6c): a key from C_CreateObject (scenario 3) or C_UnwrapKey (scenario 4)
# was in the clear outside the token, so it was never always sensitive nor never extractable; C
# read both from the current flags.
s/^\(\(ec priv flags\|ec priv p256\|ec priv p256 scalar on p384\|ed25519 priv\|ed25519 priv by name\|ed448 priv by name\|mldsa44 priv\|mlkem512 priv\|rsa priv extractable\|rsa priv full\|slhdsa sha2-128f priv\|x25519 priv\) \(ALWAYS_SENSITIVE\|NEVER_EXTRACTABLE\)\t0\t0x1\t\)01$/\100/
s/^\(uw \(allowed mechs\|des3 of 24\|generic\|kwp generic5\|label 70\|no template\|oaep\|oaep label\|template sensitive\|token\|usage\|value_len 16\) \(ALWAYS_SENSITIVE\|NEVER_EXTRACTABLE\)\t0\t0x1\t\)01$/\100/
# DIV-058 (scenario 4): a key that is not extractable is never wrapped; a public key and a data
# object carry no CKA_EXTRACTABLE, so they are refused too.
s/^\(kw not extractable\|kwp data object\)\t0\t0x18\t[0-9a-f]*$/\1\t0x6a\t0x40\t-/
s/^kwp ec pub\t0\t0x68\trnd:104$/kwp ec pub\t0x6a\t0x200\t-/
# DIV-067 (scenario 4): an unwrapped key is a secret key of a secret key type.
/^uw \(ec type\|class private\) [A-Z_]*\t/d
s/^uw ec type\t0\t+1\t-$/uw ec type\t0x13\t-\t-\nuw ec type objects\t0\t+0\t-/
s/^uw class private\t0\t+1\t-$/uw class private\t0xd1\t-\t-\nuw class private objects\t0\t+0\t-/
# DIV-050 (scenario 4): wrap and unwrap with the user's keys need the user's login (C: logged
# out 0x101, the SO 0).
s/^\(wrap logged out\|unwrap logged out\)\t0x101$/\1\t0x60/
s/^\(so wrap user key\|so unwrap with user key\)\t0$/\1\t0x60/
# Scenario 5 (slice 6d, C_DeriveKey). DIV-068: a derived key is of a secret key type, compared
# whole (0x13), and an AES key is 16, 24 or 32 bytes (0x62). DIV-057: a data object only from
# CKM_HKDF_DATA, and a key derived from a sensitive key stays sensitive (0xD1 for SENSITIVE
# FALSE); C stored each.
/^\(hkdf class data\|hkdf class data from sensitive base\|hkdf key type aes 5\|hkdf key type ec\|hkdf key type wide\|hkdf from sensitive base, sensitive false\|concat key type aes\|concat class data\|concat class data from sensitive base\|ecdh sensitive false\|ecdh class data\) [A-Z_]*\t/d
s/^\(hkdf key type ec\|hkdf key type wide\)\t0\t+1\t-$/\1\t0x13\t-\t-\n\1 objects\t0\t+0\t-/
s/^\(hkdf key type aes 5\|concat key type aes\)\t0\t+1\t-$/\1\t0x62\t-\t-\n\1 objects\t0\t+0\t-/
s/^\(hkdf class data\|hkdf class data from sensitive base\|hkdf from sensitive base, sensitive false\|concat class data\|concat class data from sensitive base\|ecdh sensitive false\|ecdh class data\)\t0\t+1\t-$/\1\t0xd1\t-\t-\n\1 objects\t0\t+0\t-/
# DIV-057: SENSITIVE from a sensitive base or second key (every EC private key is one), so the
# value no longer reads; its wrapped blob is unchanged.
s/^\(\(hkdf from sensitive base\|hkdf from sensitive base, extractable\|concat key second sensitive\|concat from sensitive base\|ecdh \(bare point\|compressed point\|octet string\|spki\|cofactor\|p521 bare\|p521 octet string\|key type aes 32\|extractable\)\) SENSITIVE\t0\t0x1\t\)00$/\101/
s/^\(hkdf from sensitive base, extractable\|ecdh extractable\) VALUE\t0\t0x20\t[0-9a-f]*$/\1 VALUE\t0x11\t0xffffffffffffffff\t-/
# DIV-057, RULE-059: every base in scenario 5 came from C_CreateObject, so no derived key was
# always sensitive or never extractable; C read both from the derived key's own flags. A data
# object (CKM_HKDF_DATA's) has no history and reads as C.
/^== scenario 5$/,/^== scenario 6$/ { /^hkdf data\( from sensitive base\)\? [A-Z_]*\t/! s/^\(.* \(ALWAYS_SENSITIVE\|NEVER_EXTRACTABLE\)\t0\t0x1\t\)01$/\100/ }
# DIV-050 (scenario 5): deriving from the user's key needs the user's login (C: logged out
# 0x101, the SO 0).
s/^hkdf logged out\t0x101$/hkdf logged out\t0x60/
s/^\(so hkdf from user key\|so concat from user key\|so ecdh from user key\)\t0$/\1\t0x60/
# DIV-066 (scenario 6): so C_EncapsulateKey refuses that key (0x68), where C's key encapsulated.
/^encap encapsulate false [A-Z_]*\t/d
s/^encap encapsulate false\t0\t+1\t0x300$/encap encapsulate false\t0x68\t-\t0x800\nencap encapsulate false objects\t0\t+0\t-/
# Scenario 6 (slice 7). RULE-037(a): no token object from a read-only session (0xB5, before the
# encapsulation, so the length is untouched). DIV-069: a KEM key is stored as a derived key: a
# secret key (0xD1), of a secret key type compared whole (0x13), at its size (RULE-020, 0x62),
# with the template's usage and metadata (a malformed date 0x13 after the add, so the handle
# is written and the key destroyed). DIV-050: the private key is the user's alone.
/^\(encap ro token\|decap ro token\|decap class \(data\|private\)\|decap key type \(aes 5\|des3\|ec\|wide\|kem\)\|decap start date short\|encap key type \(aes 5\|ec\)\|encap class data\) [A-Z_]*\t/d
s/^encap ro token\t0\t+3\t0x300$/encap ro token\t0xb5\t-\t0x800\nencap ro token objects\t0\t+0\t-/
s/^encap ro session object\t0\t+1\t0x300$/encap ro session object\t0\t+3\t0x300/
s/^decap ro token\t0\t+1\t-$/decap ro token\t0xb5\t-\t-\ndecap ro token objects\t0\t+0\t-/
s/^\(decap class \(data\|private\)\)\t0\t+1\t-$/\1\t0xd1\t-\t-\n\1 objects\t0\t+0\t-/
s/^\(decap key type \(aes 5\|des3\)\)\t0\t+1\t-$/\1\t0x62\t-\t-\n\1 objects\t0\t+0\t-/
s/^\(decap key type \(ec\|wide\|kem\)\)\t0\t+1\t-$/\1\t0x13\t-\t-\n\1 objects\t0\t+0\t-/
s/^decap start date short\t0\t+1\t-$/decap start date short\t0x13\t+1\t-\ndecap start date short objects\t0\t+0\t-/
s/^encap key type aes 5\t0\t+1\t0x300$/encap key type aes 5\t0x62\t-\t0x300\nencap key type aes 5 objects\t0\t+0\t-/
s/^encap key type ec\t0\t+1\t0x300$/encap key type ec\t0x13\t-\t0x300\nencap key type ec objects\t0\t+0\t-/
s/^encap class data\t0\t+1\t0x300$/encap class data\t0xd1\t-\t0x300\nencap class data objects\t0\t+0\t-/
s/^decap start date START_DATE\t0\t0\t-$/decap start date START_DATE\t0\t0x8\t3230323630313031/
s/^encap id and dates END_DATE\t0\t0\t-$/encap id and dates END_DATE\t0\t0x8\t3230323630313031/
s/^decap derive template DERIVE\t0\t0x1\t00$/decap derive template DERIVE\t0\t0x1\t01/
s/^decap encrypt false ENCRYPT\t0\t0x1\t01$/decap encrypt false ENCRYPT\t0\t0x1\t00/
s/^encryptinit with encrypt false\t0$/encryptinit with encrypt false\t0x68/
s/^encrypt with encrypt false\t0$/encrypt with encrypt false\t0x91/
s/^decap logged out\t0x101$/decap logged out\t0x60/
s/^so decap with user key\t0$/so decap with user key\t0x60/
