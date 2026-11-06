    /* DIV-057 (the harness copy of tests/test_ecdh_peer_point.c): a secret derived from an EC
     * private key stays in a sensitive key, so it leaves the way PKCS#11 exports a key:
     * wrapped under a session AES key, then unwrapped readable. */
    void *l = dlopen("./libfreehsm.so", RTLD_NOW);
    CK_RV (*gk)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV (*wk)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE *,
                CK_ULONG *);
    CK_RV (*uk)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE, CK_BYTE *, CK_ULONG,
                CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);
    *(void **)&gk = dlsym(l, "C_GenerateKey");
    *(void **)&wk = dlsym(l, "C_WrapKey");
    *(void **)&uk = dlsym(l, "C_UnwrapKey");
    CK_ULONG kl = 32, wl = 96;
    CK_BYTE blob[96];
    CK_ATTRIBUTE kt_[] = { { CKA_VALUE_LEN, &kl, sizeof kl } };
    CK_ATTRIBUTE ut[] = { { CKA_CLASS, &cls, sizeof cls }, { CKA_KEY_TYPE, &kt, sizeof kt },
                          { CKA_SENSITIVE, &f, 1 }, { CKA_EXTRACTABLE, &t, 1 } };
    CK_MECHANISM gm = { 0x1080UL /* CKM_AES_KEY_GEN */, NULL, 0 };
    CK_MECHANISM km = { 0x2109UL /* CKM_AES_KEY_WRAP */, NULL, 0 };
    CK_OBJECT_HANDLE kek = 0, z = 0;
    if ((rv = gk(s, &gm, kt_, 1, &kek)) || (rv = wk(s, &km, kek, k, blob, &wl))
        || (rv = uk(s, &km, kek, blob, wl, ut, 4, &z)))
        return rv;
    CK_ATTRIBUTE v = { CKA_VALUE, out, vlen };
    return C_GetAttributeValue(s, z, &v, 1);
