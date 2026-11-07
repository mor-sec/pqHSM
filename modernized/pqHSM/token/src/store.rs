//! The object store: the plaintext blob (v1 to v4 readers, v4 writer, `src/fhsm_token.c:334-934`),
//! the encrypted frame after the header (RULE-003) and the clear public section
//! (`:478-504`, `:1041-1090`). Pure functions over bytes; no I/O, no keys.
//!
//! v4 record (912 fixed bytes after a u32 `rec_len`, then the value):
//!
//! ```text
//!   0 handle   4 class   8 key_type  12 value_len  16 label[64]  80 id[32]  112 id_len
//! 116 flags  117 usage  118 flags3  119 pad  120 start[8] 128 start_len  129 end[8]
//! 137 end_len  138 app[64]  202 app_len  203 flags2
//! 204 allowed_count, allowed[8] (u32)   237 wrap_count, 4 x 56-byte entries
//! 462 unwrap_count, 4 entries           687 derive_count, 4 entries      912 value
//! ```

use std::sync::Arc;

use crate::Rv;
use crate::ffi::mem::Buf;

/// An object's value: in the secure heap when the object is sensitive (C #127), shared by
/// every copy of the store so a pointer handed to C stays put until the object leaves it, and
/// released through `fhsm_api_free_value` (RULE-078). `Debug` prints only the length.
#[derive(Clone, Default)]
pub struct Value(Option<Arc<Buf>>);

impl Value {
    pub fn new(bytes: &[u8], sensitive: bool) -> Result<Value, Rv> {
        Ok(Value(Some(Arc::new(Buf::new(bytes, sensitive)?))))
    }

    /// Held in the secure heap.
    pub fn is_secure(&self) -> bool {
        self.0.as_deref().is_some_and(Buf::secure)
    }
}

impl std::ops::Deref for Value {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.as_deref().map_or(&[], Buf::as_slice)
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        **self == **other
    }
}

impl Eq for Value {}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Value({} bytes)", self.len())
    }
}

pub const MAX_OBJECTS: usize = 1024;
pub const LABEL_LEN: usize = 64;
pub const APP_LEN: usize = 64;
/// v1 records carry a fixed 5500-byte value field.
pub const V1_VALUE_LEN: usize = 5500;
pub const V1_REC: usize = 5620;
pub const V2_FIXED: usize = 120;
pub const V3_FIXED: usize = 204;
pub const V4_FIXED: usize = 912;
pub const VALUE_MAX: usize = 2 * 1024 * 1024;
pub const POLICY_MECH_MAX: usize = 8;
pub const POLICY_ATTR_MAX: usize = 4;
pub const POLICY_VALUE_MAX: usize = 48;
pub const POLICY_ENTRY: usize = 56;
pub const BLOB_V2_MAGIC: u32 = 0xF5B2_0002;
pub const BLOB_V3_MAGIC: u32 = 0xF5B3_0003;
pub const BLOB_V4_MAGIC: u32 = 0xF5B4_0004;
pub const PUB_MAGIC: u32 = 0xF5B5_B001;
/// `FHSM_OBJ_BLOB_MAX`: the loader's bound on `ct_len`. It exceeds `INT_MAX`, and C's GCM call
/// casts to `int` (RULE-003(1)), which Phase 3 owns; Phase 2 keeps the number.
pub const BLOB_MAX: u64 = 12 + MAX_OBJECTS as u64 * (4 + V4_FIXED as u64 + VALUE_MAX as u64);

pub const CKO_CERTIFICATE: u32 = 1;
pub const CKO_PUBLIC_KEY: u32 = 2;
pub const OBJF_SENSITIVE: u8 = 0x01;
pub const OBJF2_HAS_ALLOWED_MECH: u8 = 0x08;
pub const OBJF2_HAS_WRAP_TMPL: u8 = 0x10;
pub const OBJF2_HAS_UNWRAP_TMPL: u8 = 0x20;
pub const OBJF2_HAS_DERIVE_TMPL: u8 = 0x40;

pub const KIND_NONE: u8 = 0;
pub const KIND_BOOL: u8 = 1;
pub const KIND_ULONG: u8 = 2;
pub const KIND_BYTES: u8 = 3;

/// `fhsm_policy_attr_t` (`include/fhsm_token.h`), the same layout: 56 bytes, 4-aligned.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyAttr {
    pub type_: u32,
    pub kind: u8,
    pub len: u8,
    pub value: [u8; POLICY_VALUE_MAX],
}

impl Default for PolicyAttr {
    fn default() -> Self {
        PolicyAttr {
            type_: 0,
            kind: 0,
            len: 0,
            value: [0; POLICY_VALUE_MAX],
        }
    }
}

/// One object as a record carries it (`fhsm_object_t` minus the allocator bookkeeping).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub handle: u32,
    pub class: u32,
    pub key_type: u32,
    pub label: [u8; LABEL_LEN],
    pub value: Value,
    pub id: [u8; 32],
    pub id_len: u32,
    pub flags: u8,
    pub usage: u8,
    pub flags2: u8,
    pub flags3: u8,
    pub start_date: [u8; 8],
    pub start_date_len: u8,
    pub end_date: [u8; 8],
    pub end_date_len: u8,
    pub application: [u8; APP_LEN],
    pub application_len: u8,
    pub allowed_count: u8,
    /// All eight slots as read: a v4 reader keeps slots past the count (`:890-891`).
    pub allowed: [u32; POLICY_MECH_MAX],
    pub wrap_count: u8,
    pub wrap: [PolicyAttr; POLICY_ATTR_MAX],
    pub unwrap_count: u8,
    pub unwrap: [PolicyAttr; POLICY_ATTR_MAX],
    pub derive_count: u8,
    pub derive: [PolicyAttr; POLICY_ATTR_MAX],
    /// In memory only: 0 for a token object, else the owning session (never serialised).
    pub owner_session: u32,
    /// In memory only: added by `object_add_pending` and not yet published (never serialised).
    pub pending: bool,
}

impl Default for Object {
    fn default() -> Self {
        Object {
            handle: 0,
            class: 0,
            key_type: 0,
            label: [0; LABEL_LEN],
            value: Value::default(),
            id: [0; 32],
            id_len: 0,
            flags: 0,
            usage: 0,
            flags2: 0,
            flags3: 0,
            start_date: [0; 8],
            start_date_len: 0,
            end_date: [0; 8],
            end_date_len: 0,
            application: [0; APP_LEN],
            application_len: 0,
            allowed_count: 0,
            allowed: [0; POLICY_MECH_MAX],
            wrap_count: 0,
            wrap: [PolicyAttr::default(); POLICY_ATTR_MAX],
            unwrap_count: 0,
            unwrap: [PolicyAttr::default(); POLICY_ATTR_MAX],
            derive_count: 0,
            derive: [PolicyAttr::default(); POLICY_ATTR_MAX],
            owner_session: 0,
            pending: false,
        }
    }
}

/// The decoded blob plaintext.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Store {
    pub next_handle: u32,
    pub objects: Vec<Object>,
}

const FF: Rv = Rv::FUNCTION_FAILED;
fn g32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn arr<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
    b[o..o + N].try_into().unwrap()
}

fn parse_v1(buf: &[u8]) -> Result<Store, Rv> {
    let count = g32(buf, 0) as usize;
    if count > MAX_OBJECTS {
        return Err(FF);
    }
    let next = g32(buf, 4);
    if buf.len() < 8 + count * V1_REC {
        return Err(FF);
    }
    let mut objs = Vec::new();
    let mut off = 8;
    for _ in 0..count {
        let r = &buf[off..off + V1_REC];
        let vl = g32(r, 12) as usize;
        if vl > V1_VALUE_LEN {
            return Err(FF);
        }
        let idl = g32(r, 16 + 64 + V1_VALUE_LEN + 32);
        if idl > 32 {
            return Err(FF);
        }
        objs.push(Object {
            handle: g32(r, 0),
            class: g32(r, 4),
            key_type: g32(r, 8),
            label: arr(r, 16),
            value: Value::new(
                &r[80..80 + vl],
                r[16 + 64 + V1_VALUE_LEN + 36] & OBJF_SENSITIVE != 0,
            )?,
            id: arr(r, 80 + V1_VALUE_LEN),
            id_len: idl,
            flags: r[16 + 64 + V1_VALUE_LEN + 36],
            ..Default::default()
        });
        off += V1_REC;
    }
    Ok(Store {
        next_handle: next,
        objects: objs,
    })
}

fn get_tmpl(p: &[u8]) -> Result<(u8, [PolicyAttr; POLICY_ATTR_MAX]), Rv> {
    let count = p[0];
    if count as usize > POLICY_ATTR_MAX {
        return Err(FF);
    }
    let mut a = [PolicyAttr::default(); POLICY_ATTR_MAX];
    for (k, slot) in a.iter_mut().enumerate().take(count as usize) {
        let e = &p[1 + k * POLICY_ENTRY..];
        *slot = PolicyAttr {
            type_: g32(e, 0),
            kind: e[4],
            len: e[5],
            value: arr(e, 8),
        };
        if slot.len as usize > POLICY_VALUE_MAX || slot.kind == KIND_NONE || slot.kind > KIND_BYTES
        {
            return Err(FF);
        }
        // DIV-026: only `len` bytes are the value; C handed back what followed them too
        slot.value[slot.len as usize..].fill(0);
    }
    Ok((count, a))
}

fn parse_vn(buf: &[u8], fixed: usize, ver: u32) -> Result<Store, Rv> {
    let count = g32(buf, 4) as usize;
    if count > MAX_OBJECTS {
        return Err(FF);
    }
    let next = g32(buf, 8);
    let mut off = 12usize;
    let mut objs = Vec::new();
    for _ in 0..count {
        if off + 4 > buf.len() {
            return Err(FF);
        }
        let rl = g32(buf, off) as usize;
        off += 4;
        if rl < fixed || rl > fixed + VALUE_MAX || off + rl > buf.len() {
            return Err(FF);
        }
        let r = &buf[off..off + rl];
        let vl = g32(r, 12) as usize;
        if vl != rl - fixed {
            return Err(FF);
        }
        let mut o = Object {
            handle: g32(r, 0),
            class: g32(r, 4),
            key_type: g32(r, 8),
            label: arr(r, 16),
            id: arr(r, 80),
            id_len: g32(r, 112),
            flags: r[116],
            usage: r[117],
            ..Default::default()
        };
        if o.id_len > 32 {
            return Err(FF);
        }
        if ver >= 3 {
            o.start_date = arr(r, 120);
            o.start_date_len = r[128];
            if o.start_date_len > 8 {
                return Err(FF);
            }
            o.end_date = arr(r, 129);
            o.end_date_len = r[137];
            if o.end_date_len > 8 {
                return Err(FF);
            }
            o.application = arr(r, 138);
            o.application_len = r[202];
            if o.application_len as usize > APP_LEN {
                return Err(FF);
            }
            o.flags2 = r[203];
        }
        if ver == 4 {
            o.flags3 = r[118];
            let p = &r[V3_FIXED..];
            o.allowed_count = p[0];
            if o.allowed_count as usize > POLICY_MECH_MAX {
                return Err(FF);
            }
            for k in 0..POLICY_MECH_MAX {
                o.allowed[k] = g32(p, 1 + k * 4);
            }
            let step = 1 + POLICY_ATTR_MAX * POLICY_ENTRY;
            let q = 1 + POLICY_MECH_MAX * 4;
            (o.wrap_count, o.wrap) = get_tmpl(&p[q..])?;
            (o.unwrap_count, o.unwrap) = get_tmpl(&p[q + step..])?;
            (o.derive_count, o.derive) = get_tmpl(&p[q + 2 * step..])?;
        }
        o.value = Value::new(&r[fixed..], o.flags & OBJF_SENSITIVE != 0)?;
        objs.push(o);
        off += rl;
    }
    Ok(Store {
        next_handle: next,
        objects: objs,
    })
}

pub fn parse(plaintext: &[u8]) -> Result<Store, Rv> {
    let b = plaintext;
    if b.len() < 8 {
        return Err(FF);
    }
    let m = g32(b, 0);
    let v = match m {
        BLOB_V4_MAGIC => 4,
        BLOB_V3_MAGIC => 3,
        BLOB_V2_MAGIC => 2,
        _ => return parse_v1(b),
    };
    if b.len() < 12 {
        return Err(FF);
    }
    parse_vn(b, [0, 0, V2_FIXED, V3_FIXED, V4_FIXED][v], v as u32)
}

fn put_tmpl(out: &mut Vec<u8>, count: u8, a: &[PolicyAttr; POLICY_ATTR_MAX]) {
    out.push(count);
    for (k, at) in a.iter().enumerate() {
        let mut e = [0u8; POLICY_ENTRY];
        if k < count as usize {
            e[..4].copy_from_slice(&at.type_.to_le_bytes());
            e[4] = at.kind;
            e[5] = at.len;
            let n = (at.len as usize).min(POLICY_VALUE_MAX);
            e[8..8 + n].copy_from_slice(&at.value[..n]);
        }
        out.extend_from_slice(&e);
    }
}

pub fn serialize(store: &Store, public_only: bool) -> Vec<u8> {
    let sel: Vec<&Object> = store
        .objects
        .iter()
        .filter(|o| {
            if public_only {
                is_public(o)
            } else {
                o.owner_session == 0 && !o.pending
            }
        })
        .collect();
    // Exactly one allocation: a reallocation would free a copy of plaintext key values
    // unzeroised (review M2). The caller wraps the result in Zeroizing.
    let len = 12
        + sel
            .iter()
            .map(|o| 4 + V4_FIXED + o.value.len())
            .sum::<usize>();
    let mut out = Vec::with_capacity(len);
    let cap = out.capacity();
    out.extend(BLOB_V4_MAGIC.to_le_bytes());
    out.extend((sel.len() as u32).to_le_bytes());
    out.extend(store.next_handle.to_le_bytes());
    for o in sel {
        out.extend(((V4_FIXED + o.value.len()) as u32).to_le_bytes());
        for v in [o.handle, o.class, o.key_type, o.value.len() as u32] {
            out.extend(v.to_le_bytes());
        }
        out.extend(o.label);
        out.extend(o.id);
        out.extend(o.id_len.to_le_bytes());
        out.extend([o.flags, o.usage, o.flags3, 0]);
        out.extend(o.start_date);
        out.push(o.start_date_len);
        out.extend(o.end_date);
        out.push(o.end_date_len);
        out.extend(o.application);
        out.push(o.application_len);
        out.push(o.flags2);
        out.push(o.allowed_count);
        for k in 0..POLICY_MECH_MAX {
            out.extend(
                (if k < o.allowed_count as usize {
                    o.allowed[k]
                } else {
                    0
                })
                .to_le_bytes(),
            );
        }
        put_tmpl(&mut out, o.wrap_count, &o.wrap);
        put_tmpl(&mut out, o.unwrap_count, &o.unwrap);
        put_tmpl(&mut out, o.derive_count, &o.derive);
        out.extend_from_slice(&o.value);
    }
    debug_assert_eq!((out.len(), out.capacity()), (len, cap));
    out
}

/// RULE-055's private classes: CKO_PRIVATE_KEY and CKO_SECRET_KEY.
pub fn is_private_class(class: u32) -> bool {
    class == 3 || class == 4
}

pub fn is_public(o: &Object) -> bool {
    o.owner_session == 0
        && !o.pending
        && (o.class == CKO_PUBLIC_KEY || o.class == CKO_CERTIFICATE)
        && o.flags & OBJF_SENSITIVE == 0
}

pub fn public_section(store: &Store) -> Vec<u8> {
    let b = serialize(store, true);
    [
        &PUB_MAGIC.to_le_bytes()[..],
        &(b.len() as u32).to_le_bytes(),
        &b,
    ]
    .concat()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blob<'a> {
    pub nonce: [u8; 12],
    pub ct: &'a [u8],
    pub tag: [u8; 16],
}

pub fn split_blob(file: &[u8]) -> Result<Option<Blob<'_>>, Rv> {
    const H: usize = crate::header::LEN;
    if file.len() <= H {
        return Ok(None);
    }
    if file.len() < H + 16 {
        return Err(FF);
    }
    let ct = g32(file, H) as u64;
    if ct == 0 || ct > BLOB_MAX || (file.len() as u64) < (H as u64 + 16 + ct + 16) {
        return Err(FF);
    }
    let ct = ct as usize;
    Ok(Some(Blob {
        nonce: arr(file, H + 4),
        ct: &file[H + 16..H + 16 + ct],
        tag: arr(file, H + 16 + ct),
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicView {
    Empty,
    Objects(Store),
    Unknown,
}

pub fn read_public_view(file: &[u8]) -> PublicView {
    const H: usize = crate::header::LEN;
    let n = file.len() as u64;
    if file.len() == H {
        return PublicView::Empty;
    }
    if file.len() <= H + 16 {
        return PublicView::Unknown;
    }
    let ct = g32(file, H) as u64;
    if ct == 0 || ct > BLOB_MAX {
        return PublicView::Unknown;
    }
    let po = H as u64 + 16 + ct + 16;
    if n < po + 8 {
        return PublicView::Unknown;
    }
    let po = po as usize;
    let len = g32(file, po + 4) as u64;
    if g32(file, po) != PUB_MAGIC || !(12..=BLOB_MAX).contains(&len) || po as u64 + 8 + len != n {
        return PublicView::Unknown;
    }
    let pt = &file[po + 8..];
    if g32(pt, 0) != BLOB_V4_MAGIC {
        return PublicView::Unknown;
    }
    match parse(pt) {
        Ok(s) if s.objects.iter().all(is_public) => PublicView::Objects(s),
        _ => PublicView::Unknown,
    }
}
