//! A small, self-contained parser for the raw BTF binary format
//! (`/sys/kernel/btf/vmlinux`), used only to answer one question: "what byte offset does
//! `struct.field` have, and what integer value does `enum::VARIANT` have, on THIS node's
//! kernel?" (ADR-0014 amendment, load-time BTF preflight.)
//!
//! Neither `aya::Btf` nor `aya-obj::Btf`'s public API answers that: `aya-obj` 0.2.1's
//! `BtfType`/`BtfMember`/`Struct::members`/`Union::members` are all `pub(crate)`, and
//! `Btf::type_by_id` / `Btf::types()` are `pub(crate)` too (aya only needs to hand a `Btf`
//! to the kernel verifier, not answer field-offset questions from Rust — its one public
//! lookup, `id_by_type_name_kind`, returns a type id with no public way to read what that
//! id's members are). So this module parses the BTF type section directly, per the format
//! documented at <https://www.kernel.org/doc/html/latest/bpf/btf.html>. It only decodes
//! the handful of kinds the preflight table needs (STRUCT, UNION, ENUM, ENUM64) plus the
//! "see-through" kinds (TYPEDEF/CONST/VOLATILE/RESTRICT) needed to resolve an anonymous
//! member's type to the struct/union it wraps — every other kind is still walked (its
//! encoded length must be computed to find the next type) but its payload is discarded.

use std::fmt;

const BTF_MAGIC: u16 = 0xeb9f;
const HEADER_LEN: usize = 24;

const KIND_STRUCT: u8 = 4;
const KIND_UNION: u8 = 5;
const KIND_ENUM: u8 = 6;
const KIND_TYPEDEF: u8 = 8;
const KIND_VOLATILE: u8 = 9;
const KIND_CONST: u8 = 10;
const KIND_RESTRICT: u8 = 11;
const KIND_FUNC_PROTO: u8 = 13;
const KIND_VAR: u8 = 14;
const KIND_DATASEC: u8 = 15;
const KIND_DECL_TAG: u8 = 17;
const KIND_ENUM64: u8 = 19;
// PTR(2), ARRAY(3, handled by its own 12-byte extra below), FWD(7), FUNC(12), FLOAT(16),
// TYPE_TAG(18), and the unnamed KIND_INT(1) all fall through to the generic 0/4/12-byte
// "opaque" arms below — see `parse_types`.
const KIND_INT: u8 = 1;
const KIND_ARRAY: u8 = 3;

/// Why parsing a BTF blob failed. Any of these is treated identically by the caller
/// ([`super::check_bytes`]): fail closed on every struct-reading probe (ADR-0014's
/// degrade-gracefully — never crash, never trust an offset we couldn't independently
/// re-derive).
#[derive(Debug)]
pub enum BtfParseError {
    /// Shorter than a BTF header.
    TooShort,
    /// The first two bytes aren't the BTF magic in either byte order.
    BadMagic,
    /// A header offset/length points outside the blob, or a type's declared member/
    /// variant count runs past the type section's end.
    Truncated,
}

impl fmt::Display for BtfParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "shorter than a BTF header"),
            Self::BadMagic => write!(f, "not a BTF blob (bad magic)"),
            Self::Truncated => write!(f, "truncated or self-inconsistent BTF type section"),
        }
    }
}

impl std::error::Error for BtfParseError {}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u32(self, b: &[u8]) -> u32 {
        let a: [u8; 4] = b.try_into().expect("4-byte slice");
        match self {
            Self::Little => u32::from_le_bytes(a),
            Self::Big => u32::from_be_bytes(a),
        }
    }

    fn i32(self, b: &[u8]) -> i32 {
        self.u32(b) as i32
    }
}

/// A decoded struct/union member: its name (empty ⇒ anonymous), the type id of its own
/// type, and its byte offset within the containing struct/union. BTF's bitfield-size
/// encoding is discarded — nothing this preflight ever reads is a bitfield, so only the
/// (always byte-aligned, in practice) offset matters.
struct Member {
    name: String,
    type_id: u32,
    byte_offset: u32,
}

/// A decoded enum variant: its name and signed value — covers both the 32-bit
/// `BTF_KIND_ENUM` and the 64-bit `BTF_KIND_ENUM64`.
struct EnumVariant {
    name: String,
    value: i64,
}

/// What's kept about one parsed BTF type — only what the preflight ever asks for.
enum Decoded {
    Struct(Vec<Member>),
    Union(Vec<Member>),
    Enum(Vec<EnumVariant>),
    /// A "see-through" type (typedef/const/volatile/restrict) forwarding to `type_id` —
    /// the only kinds an anonymous member's type is resolved through when the walk is
    /// looking for the struct/union underneath.
    Forward(u32),
    /// Every other kind: still correctly skipped during parsing, payload discarded.
    Opaque,
}

struct RawType {
    name: String,
    kind: Decoded,
}

/// A parsed BTF blob, queried by struct-field and enum-variant name. Built once from raw
/// bytes ([`RawBtf::parse`]) at agent startup, before any probe attaches.
pub struct RawBtf {
    /// `types[i]` is BTF type id `i + 1` (id `0` is the implicit `void`, never stored).
    types: Vec<RawType>,
}

impl RawBtf {
    /// Parse a raw BTF blob (the bytes of `/sys/kernel/btf/vmlinux`, or a test fixture in
    /// the same format). Detects endianness from the magic bytes rather than assuming the
    /// host's — the same blob is valid on either fleet arch.
    pub fn parse(data: &[u8]) -> Result<Self, BtfParseError> {
        if data.len() < HEADER_LEN {
            return Err(BtfParseError::TooShort);
        }
        let endian = if u16::from_le_bytes([data[0], data[1]]) == BTF_MAGIC {
            Endian::Little
        } else if u16::from_be_bytes([data[0], data[1]]) == BTF_MAGIC {
            Endian::Big
        } else {
            return Err(BtfParseError::BadMagic);
        };
        let hdr_len = endian.u32(&data[4..8]) as usize;
        let type_off = endian.u32(&data[8..12]) as usize;
        let type_len = endian.u32(&data[12..16]) as usize;
        let str_off = endian.u32(&data[16..20]) as usize;
        let str_len = endian.u32(&data[20..24]) as usize;

        let type_start = hdr_len
            .checked_add(type_off)
            .ok_or(BtfParseError::Truncated)?;
        let type_end = type_start
            .checked_add(type_len)
            .ok_or(BtfParseError::Truncated)?;
        let str_start = hdr_len
            .checked_add(str_off)
            .ok_or(BtfParseError::Truncated)?;
        let str_end = str_start
            .checked_add(str_len)
            .ok_or(BtfParseError::Truncated)?;
        if type_end > data.len() || str_end > data.len() {
            return Err(BtfParseError::Truncated);
        }

        let strings = &data[str_start..str_end];
        let types = Self::parse_types(&data[type_start..type_end], strings, endian)?;
        Ok(Self { types })
    }

    /// Read a NUL-terminated string at `offset` into `strings`. An out-of-range or
    /// unterminated offset yields `""` rather than an error — a cosmetic-only failure
    /// (a name that can't be read just never matches anything the preflight looks up).
    fn string_at(strings: &[u8], offset: u32) -> String {
        let start = offset as usize;
        let Some(rest) = strings.get(start..) else {
            return String::new();
        };
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        String::from_utf8_lossy(&rest[..end]).into_owned()
    }

    fn parse_types(
        mut buf: &[u8],
        strings: &[u8],
        endian: Endian,
    ) -> Result<Vec<RawType>, BtfParseError> {
        let mut out = Vec::new();
        while !buf.is_empty() {
            if buf.len() < 12 {
                return Err(BtfParseError::Truncated);
            }
            let name_off = endian.u32(&buf[0..4]);
            let info = endian.u32(&buf[4..8]);
            let extra = endian.u32(&buf[8..12]);
            let kind = ((info >> 24) & 0x1f) as u8;
            let kind_flag = (info >> 31) & 1 == 1;
            let vlen = (info & 0xffff) as usize;
            let mut consumed = 12usize;

            let decoded = match kind {
                KIND_STRUCT | KIND_UNION => {
                    let need = vlen.checked_mul(12).ok_or(BtfParseError::Truncated)?;
                    if buf.len() < consumed + need {
                        return Err(BtfParseError::Truncated);
                    }
                    let mut members = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let base = consumed + i * 12;
                        let m_name = endian.u32(&buf[base..base + 4]);
                        let m_type = endian.u32(&buf[base + 4..base + 8]);
                        let m_off = endian.u32(&buf[base + 8..base + 12]);
                        // kind_flag set ⇒ the low 24 bits are the bit-offset (high 8 the
                        // bitfield size, discarded); unset ⇒ the whole word is the plain
                        // bit-offset. Either way this crate's targets are never
                        // bitfields, so only the offset survives.
                        let bit_offset = if kind_flag {
                            m_off & 0x00ff_ffff
                        } else {
                            m_off
                        };
                        members.push(Member {
                            name: Self::string_at(strings, m_name),
                            type_id: m_type,
                            byte_offset: bit_offset / 8,
                        });
                    }
                    consumed += need;
                    if kind == KIND_STRUCT {
                        Decoded::Struct(members)
                    } else {
                        Decoded::Union(members)
                    }
                }
                KIND_ENUM => {
                    let need = vlen.checked_mul(8).ok_or(BtfParseError::Truncated)?;
                    if buf.len() < consumed + need {
                        return Err(BtfParseError::Truncated);
                    }
                    let mut variants = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let base = consumed + i * 8;
                        let v_name = endian.u32(&buf[base..base + 4]);
                        let v_val = endian.i32(&buf[base + 4..base + 8]);
                        variants.push(EnumVariant {
                            name: Self::string_at(strings, v_name),
                            value: v_val as i64,
                        });
                    }
                    consumed += need;
                    Decoded::Enum(variants)
                }
                KIND_ENUM64 => {
                    let need = vlen.checked_mul(12).ok_or(BtfParseError::Truncated)?;
                    if buf.len() < consumed + need {
                        return Err(BtfParseError::Truncated);
                    }
                    let mut variants = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let base = consumed + i * 12;
                        let v_name = endian.u32(&buf[base..base + 4]);
                        let lo = endian.u32(&buf[base + 4..base + 8]) as u64;
                        let hi = endian.u32(&buf[base + 8..base + 12]) as u64;
                        variants.push(EnumVariant {
                            name: Self::string_at(strings, v_name),
                            value: ((hi << 32) | lo) as i64,
                        });
                    }
                    consumed += need;
                    Decoded::Enum(variants)
                }
                KIND_TYPEDEF | KIND_CONST | KIND_RESTRICT | KIND_VOLATILE => {
                    Decoded::Forward(extra)
                }
                KIND_INT => {
                    consumed += 4; // one extra word: encoding/offset/bits, unused here
                    Decoded::Opaque
                }
                KIND_ARRAY => {
                    consumed += 12; // btf_array: element type, index type, nelems
                    Decoded::Opaque
                }
                KIND_FUNC_PROTO => {
                    let need = vlen.checked_mul(8).ok_or(BtfParseError::Truncated)?; // btf_param
                    if buf.len() < consumed + need {
                        return Err(BtfParseError::Truncated);
                    }
                    consumed += need;
                    Decoded::Opaque
                }
                KIND_DATASEC => {
                    let need = vlen.checked_mul(12).ok_or(BtfParseError::Truncated)?; // btf_var_secinfo
                    if buf.len() < consumed + need {
                        return Err(BtfParseError::Truncated);
                    }
                    consumed += need;
                    Decoded::Opaque
                }
                KIND_VAR => {
                    consumed += 4; // linkage
                    Decoded::Opaque
                }
                KIND_DECL_TAG => {
                    consumed += 4; // component_idx
                    Decoded::Opaque
                }
                // PTR/FWD/FUNC/FLOAT/TYPE_TAG (and BTF_KIND_UNKN(0), any future kind)
                // have no trailing payload beyond the 12-byte fixed prefix already read.
                _ => Decoded::Opaque,
            };

            if buf.len() < consumed {
                return Err(BtfParseError::Truncated);
            }
            out.push(RawType {
                name: Self::string_at(strings, name_off),
                kind: decoded,
            });
            buf = &buf[consumed..];
        }
        Ok(out)
    }

    fn decoded(&self, type_id: u32) -> Option<&Decoded> {
        if type_id == 0 {
            return None; // the implicit `void` type — never a struct/union/enum
        }
        self.types.get((type_id - 1) as usize).map(|t| &t.kind)
    }

    /// Find the first `KIND_STRUCT` type named `name` and return its 1-based type id.
    /// `HashMap`-free linear scan: this runs once at agent startup against a
    /// (large but bounded) live-kernel BTF, not per-event.
    fn struct_id(&self, name: &str) -> Option<u32> {
        self.types.iter().enumerate().find_map(|(i, t)| {
            (t.name == name && matches!(t.kind, Decoded::Struct(_))).then_some((i + 1) as u32)
        })
    }

    fn enum_id(&self, name: &str) -> Option<u32> {
        self.types.iter().enumerate().find_map(|(i, t)| {
            (t.name == name && matches!(t.kind, Decoded::Enum(_))).then_some((i + 1) as u32)
        })
    }

    /// Follow `Forward` (typedef/const/volatile/restrict) links from `type_id` to the
    /// struct/union underneath, or `None` if it never resolves to one. Bounded so a
    /// malformed/cyclic blob can't loop forever.
    fn resolve_to_aggregate(&self, mut type_id: u32) -> Option<u32> {
        for _ in 0..16 {
            match self.decoded(type_id)? {
                Decoded::Struct(_) | Decoded::Union(_) => return Some(type_id),
                Decoded::Forward(to) => type_id = *to,
                _ => return None,
            }
        }
        None
    }

    /// How many anonymous-member levels [`member_offset`] will recurse into. Every
    /// binding this crate has ever needed is at most one level deep (`inode.i_nlink`'s
    /// anonymous union), but a malformed or adversarial BTF blob could otherwise encode a
    /// self-referential chain of anonymous members and recurse without bound — a stack
    /// overflow, which would crash the agent outright rather than degrade gracefully
    /// (ADR-0014). This cap turns that into an ordinary "field not found" instead. `/sys/
    /// kernel/btf/vmlinux` is kernel-generated and root-owned, not attacker-controlled in
    /// the normal threat model, but the parser doesn't rely on that to stay safe.
    const MAX_MEMBER_RECURSION: u8 = 16;

    /// The byte offset of `field` within the struct/union at `type_id`, recursing into
    /// any anonymous (nameless) member that itself resolves to a struct/union —
    /// `inode.i_nlink`'s anonymous union is exactly this shape. Returns the FIRST match
    /// found in declaration order. Bounded by [`Self::MAX_MEMBER_RECURSION`].
    fn member_offset(&self, type_id: u32, field: &str) -> Option<u32> {
        self.member_offset_bounded(type_id, field, Self::MAX_MEMBER_RECURSION)
    }

    fn member_offset_bounded(&self, type_id: u32, field: &str, budget: u8) -> Option<u32> {
        let budget = budget.checked_sub(1)?;
        let members = match self.decoded(type_id)? {
            Decoded::Struct(m) | Decoded::Union(m) => m,
            _ => return None,
        };
        for m in members {
            if m.name == field {
                return Some(m.byte_offset);
            }
            if m.name.is_empty()
                && let Some(inner_id) = self.resolve_to_aggregate(m.type_id)
                && let Some(inner_off) = self.member_offset_bounded(inner_id, field, budget)
            {
                return Some(m.byte_offset + inner_off);
            }
        }
        None
    }

    /// The byte offset of `struct_name.field` in this BTF, or `None` if the struct isn't
    /// present or has no member (directly, or via anonymous-union/struct recursion) named
    /// `field`.
    pub fn struct_field_offset(&self, struct_name: &str, field: &str) -> Option<u32> {
        let id = self.struct_id(struct_name)?;
        self.member_offset(id, field)
    }

    /// The value of `enum_name::variant` in this BTF (either `BTF_KIND_ENUM` or the
    /// 64-bit `BTF_KIND_ENUM64` — both decode into the same [`Decoded::Enum`]), or `None`
    /// if the enum or variant isn't present.
    pub fn enum_value(&self, enum_name: &str, variant: &str) -> Option<i64> {
        let id = self.enum_id(enum_name)?;
        match self.decoded(id)? {
            Decoded::Enum(variants) => variants.iter().find(|v| v.name == variant).map(|v| v.value),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "btf_tests.rs"]
mod tests;
