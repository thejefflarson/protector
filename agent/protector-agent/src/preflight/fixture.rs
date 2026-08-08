//! Test-only: a tiny builder for synthetic BTF blobs, encoded in the same binary format
//! [`super::btf::RawBtf::parse`] reads (little-endian, per
//! <https://www.kernel.org/doc/html/latest/bpf/btf.html>). Lets the preflight's unit
//! tests exercise the real parser and lookup logic against a hand-built "kernel" — no
//! live node, no `bpftool`, no root — so the offset-self-verification the module exists
//! to provide is itself off-fleet testable.

/// KIND numbers duplicated from `btf.rs` rather than `pub(crate)`-exposing them there —
/// this file is the only other place that needs to encode (not decode) them, and keeping
/// the encoder self-contained means a fixture test can never accidentally pass because a
/// shared constant was wrong on both sides.
mod kind {
    pub const STRUCT: u32 = 4;
    pub const UNION: u32 = 5;
    pub const ENUM: u32 = 6;
    pub const TYPEDEF: u32 = 8;
}

/// Builds one synthetic BTF blob. Types are appended in declaration order and get
/// sequential 1-based ids, matching real BTF's id assignment.
#[derive(Default)]
pub(crate) struct BtfBuilder {
    strings: Vec<u8>,
    types: Vec<u8>,
    next_id: u32,
}

impl BtfBuilder {
    pub(crate) fn new() -> Self {
        // Offset 0 in the string table is always the empty string (BTF convention;
        // `name_off == 0` means "anonymous").
        Self {
            strings: vec![0],
            ..Default::default()
        }
    }

    /// The id the NEXT `add_*` call will assign — lets a test build a self-referential or
    /// cyclic type (a member pointing at a type not created yet) by predicting its id
    /// ahead of time.
    pub(crate) fn next_id(&self) -> u32 {
        self.next_id + 1
    }

    fn add_string(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(s.as_bytes());
        self.strings.push(0);
        off
    }

    fn alloc_id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    /// Append a `BTF_KIND_STRUCT` or `BTF_KIND_UNION` type. `members`: `(name, type_id,
    /// byte_offset)` — `type_id` only matters for an ANONYMOUS member the test wants the
    /// parser to recurse into (a named member's type is never chased); `byte_offset` is
    /// encoded as a plain bit-offset (`kind_flag` unset — no bitfields, matching every
    /// real binding this preflight ever checks). Returns the new type's 1-based id.
    pub(crate) fn add_struct(
        &mut self,
        name: &str,
        is_union: bool,
        members: &[(&str, u32, u32)],
    ) -> u32 {
        let id = self.alloc_id();
        let name_off = self.add_string(name);
        let kind = if is_union { kind::UNION } else { kind::STRUCT };
        let info = (kind << 24) | (members.len() as u32 & 0xffff);
        self.types.extend_from_slice(&name_off.to_le_bytes());
        self.types.extend_from_slice(&info.to_le_bytes());
        self.types.extend_from_slice(&0u32.to_le_bytes()); // size — unused by the preflight
        for (m_name, m_type, m_byte_off) in members {
            let m_name_off = self.add_string(m_name);
            self.types.extend_from_slice(&m_name_off.to_le_bytes());
            self.types.extend_from_slice(&m_type.to_le_bytes());
            self.types
                .extend_from_slice(&(m_byte_off * 8).to_le_bytes());
        }
        id
    }

    /// Append a `BTF_KIND_TYPEDEF` forwarding to `to` — the "see-through" kind the parser
    /// resolves an anonymous member's type through.
    pub(crate) fn add_typedef(&mut self, name: &str, to: u32) -> u32 {
        let id = self.alloc_id();
        let name_off = self.add_string(name);
        let info = kind::TYPEDEF << 24;
        self.types.extend_from_slice(&name_off.to_le_bytes());
        self.types.extend_from_slice(&info.to_le_bytes());
        self.types.extend_from_slice(&to.to_le_bytes());
        id
    }

    /// Append a `BTF_KIND_ENUM` type with `(name, value)` variants.
    pub(crate) fn add_enum(&mut self, name: &str, variants: &[(&str, i32)]) -> u32 {
        let id = self.alloc_id();
        let name_off = self.add_string(name);
        let info = (kind::ENUM << 24) | (variants.len() as u32 & 0xffff);
        self.types.extend_from_slice(&name_off.to_le_bytes());
        self.types.extend_from_slice(&info.to_le_bytes());
        self.types.extend_from_slice(&4u32.to_le_bytes()); // size: 4-byte enum
        for (v_name, v_val) in variants {
            let v_name_off = self.add_string(v_name);
            self.types.extend_from_slice(&v_name_off.to_le_bytes());
            self.types.extend_from_slice(&v_val.to_le_bytes());
        }
        id
    }

    /// Encode the finished blob as a full little-endian BTF binary (header, then the type
    /// section, then the string section) — what [`super::btf::RawBtf::parse`] (and a real
    /// `/sys/kernel/btf/vmlinux`) expects.
    pub(crate) fn build(self) -> Vec<u8> {
        const HEADER_LEN: u32 = 24;
        let type_len = self.types.len() as u32;
        let str_len = self.strings.len() as u32;
        let mut out =
            Vec::with_capacity(HEADER_LEN as usize + self.types.len() + self.strings.len());
        out.extend_from_slice(&0xeb9fu16.to_le_bytes()); // magic
        out.push(1); // version
        out.push(0); // flags
        out.extend_from_slice(&HEADER_LEN.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // type_off: types start right after the header
        out.extend_from_slice(&type_len.to_le_bytes());
        out.extend_from_slice(&type_len.to_le_bytes()); // str_off: strings start right after types
        out.extend_from_slice(&str_len.to_le_bytes());
        out.extend_from_slice(&self.types);
        out.extend_from_slice(&self.strings);
        out
    }
}
