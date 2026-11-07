# C's contract.sh transcript to the hybrid's: the recorded divergences a consumer sees (step 11).
# DIV-059: ulMinPinLen is 8 (pkcs11-tool -L, direct and through p11-kit).
s|^\(  pin min/max        : \)4/64$|\18/64|
# RULE-014: in the strict build CKM_GENERIC_SECRET_KEY_GEN advertises 14 bytes at least.
s|^\(  GENERIC-SECRET-KEY-GEN, keySize={\)1,64}|\114,64}|
