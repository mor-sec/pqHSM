//! A CAVP SHA-256 response file read as `kat/fhsm_kat_vectors.c:288-349` reads it: lines of
//! at most 2047 bytes (`fgets` into 2048, so a longer line goes on as a line of its own),
//! `Len` through glibc's `atoi`, `Msg` and `MD` two hex characters at a time through glibc's
//! `sscanf("%2x")`. A Msg or MD that stops early keeps the previous record's bytes after it,
//! and the records repeat C's flags: Len starts one; Msg and MD complete it, in either order.
//! C's skip of `#`, blank and `[` lines is not repeated: no such line starts a field, and a
//! record completes only on the line that sets its last field.

/// `fgets`' buffer.
const LINE: usize = 2048;
/// C's `msg[256]`.
const MSG_MAX: usize = 256;

/// One complete record.
pub struct Vector<'r> {
    pub bits: i32,
    /// `None`: `Len` asks for more than the 256-byte buffer, or below -14 (a negative length), which C
    /// hashes past the end of its buffer (DIV-047).
    pub msg: Option<&'r [u8]>,
    pub md: &'r [u8; 32],
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    // what C keeps across lines and records: the line buffer is read past its NUL in one case
    // (an odd Msg at the end of a line), so it persists too
    line: [u8; LINE],
    msg: [u8; MSG_MAX],
    md: [u8; 32],
    bits: i32,
    /// `(msg_bits + 7) / 8`, as C's int before it becomes a size_t.
    msg_len: i64,
    have: [bool; 3],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            line: [0; LINE],
            msg: [0; MSG_MAX],
            md: [0; 32],
            bits: 0,
            msg_len: 0,
            have: [false; 3],
        }
    }

    /// `fgets`: up to 2047 bytes, through a newline; false at the end of the file.
    fn next_line(&mut self) -> bool {
        let rest = &self.data[self.pos..];
        if rest.is_empty() {
            return false;
        }
        let max = rest.len().min(LINE - 1);
        let n = rest[..max]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(max, |i| i + 1);
        self.line[..n].copy_from_slice(&rest[..n]);
        self.line[n] = 0;
        self.pos += n;
        true
    }

    pub fn next_vector(&mut self) -> Option<Vector<'_>> {
        loop {
            if !self.next_line() {
                return None;
            }
            let line = &self.line;
            if line.starts_with(b"Len = ") {
                self.bits = atoi(&line[6..]);
                self.msg_len = (i64::from(self.bits) + 7) / 8;
                self.have = [true, false, false];
            } else if line.starts_with(b"Msg = ") {
                // a negative length is a huge size_t: the 256-byte bound applies
                let n = usize::try_from(self.msg_len).map_or(MSG_MAX, |n| n.min(MSG_MAX));
                for k in 0..n {
                    let Some(b) = hex2(line, 6 + 2 * k) else {
                        break;
                    };
                    self.msg[k] = b;
                }
                self.have[1] = true;
            } else if line.starts_with(b"MD = ") {
                for k in 0..32 {
                    let Some(b) = hex2(line, 5 + 2 * k) else {
                        break;
                    };
                    self.md[k] = b;
                }
                self.have[2] = true;
            }
            if self.have == [true; 3] {
                self.have = [false; 3];
                let msg = usize::try_from(self.msg_len)
                    .ok()
                    .filter(|&n| n <= MSG_MAX)
                    .map(|n| &self.msg[..n]);
                return Some(Vector {
                    bits: self.bits,
                    msg,
                    md: &self.md,
                });
            }
        }
    }
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// glibc's `atoi`: `(int)strtol(s, NULL, 10)`, saturating at the long's range, then truncated.
fn atoi(s: &[u8]) -> i32 {
    let mut i = s.iter().position(|&b| !is_space(b)).unwrap_or(s.len());
    let neg = matches!(s.get(i), Some(b'-'));
    if matches!(s.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let mut v: i64 = 0;
    for &b in s[i..].iter().take_while(|b| b.is_ascii_digit()) {
        let d = i64::from(b - b'0');
        v = if neg {
            v.saturating_mul(10).saturating_sub(d)
        } else {
            v.saturating_mul(10).saturating_add(d)
        };
    }
    v as i32
}

/// glibc's `sscanf(line + at, "%2x", &b)` stored into a byte: leading white space skipped, then
/// at most two characters of an optional sign and hex digits (the `0x` prefix glibc also takes
/// fits no digit after it in two characters, so it reads as the digit 0 here too). `None`
/// where sscanf does not return 1, at the end of the string or without a digit.
fn hex2(line: &[u8; LINE], mut at: usize) -> Option<u8> {
    let c = |i: usize| line.get(i).copied().unwrap_or(0);
    while is_space(c(at)) {
        at += 1;
    }
    let mut width = 2;
    let neg = c(at) == b'-';
    let mut digits = 0;
    if matches!(c(at), b'+' | b'-') {
        at += 1;
        width -= 1;
    }
    let mut v: u32 = 0;
    while width > 0 && c(at).is_ascii_hexdigit() {
        v = v * 16 + char::from(c(at)).to_digit(16).unwrap_or(0);
        at += 1;
        width -= 1;
        digits += 1;
    }
    (digits > 0).then(|| if neg { v.wrapping_neg() } else { v } as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Option<u8> {
        let mut line = [0; LINE];
        line[..s.len()].copy_from_slice(s.as_bytes());
        hex2(&line, 0)
    }

    /// glibc's %2x, case by case (the goldens see the bytes these produce).
    #[test]
    fn hex2_reads_as_glibc_does() {
        assert_eq!(h("61"), Some(0x61));
        assert_eq!(h(" 6162"), Some(0x61));
        assert_eq!(h("+1ff"), Some(1));
        assert_eq!(h("-1"), Some(0xff));
        assert_eq!(h("0x41"), Some(0));
        assert_eq!(h("6"), Some(6));
        assert_eq!(h("zz"), None);
        assert_eq!(h("+z"), None);
        assert_eq!(h("\n"), None);
        assert_eq!(h(""), None);
    }

    /// fgets(2048): a line of 2047 bytes and its newline arrive as two lines.
    #[test]
    fn a_line_is_at_most_2047_bytes() {
        let mut data = vec![b'#'; 2047];
        data.extend(b"\nLen = 8\n");
        let mut r = Reader::new(&data);
        let mut lens = Vec::new();
        while r.next_line() {
            lens.push(r.line.iter().position(|&b| b == 0).unwrap());
        }
        assert_eq!(lens, [2047, 1, 8]);
    }

    #[test]
    fn atoi_saturates_then_truncates_as_glibc_does() {
        assert_eq!(atoi(b"  24\n"), 24);
        assert_eq!(atoi(b"-8"), -8);
        assert_eq!(atoi(b"x"), 0);
        assert_eq!(atoi(b"99999999999"), 99_999_999_999_i64 as i32);
        assert_eq!(atoi(b"99999999999999999999"), -1);
    }
}
