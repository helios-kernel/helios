extern crate alloc;

use crate::{IpAddress, Ipv4Address, Ipv6Address};
use arrayvec::ArrayVec;

pub const DNS_PORT: u16 = 53;
/// Default TCP/UDP port for `https` origins, which queries `host` directly
/// rather than `_<port>._https.<host>` (RFC 9460 section 9.1).
pub const HTTPS_DEFAULT_PORT: u16 = 443;
/// Maximum address records collected from one response, across both
/// address families.
pub const DNS_MAX_ADDRESS_RECORDS: usize = 32;
/// Maximum ALPN protocol identifiers collected from one `HTTPS` record.
pub const DNS_MAX_ALPN_IDS: usize = 16;

/// `CNAME` and `AliasMode` links one lookup may chain from the queried name:
/// Unbound's default `max-query-restarts`, the limit it puts on the chain it
/// will follow. A longer chain is not followed and its far end is not trusted.
pub const DNS_MAX_CNAME_CHAIN: usize = 11;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const TYPE_HTTPS: u16 = 65;
const CLASS_IN: u16 = 1;
/// The first question starts right after the 12-byte header (RFC 1035
/// section 4.1.1).
const QUESTION_OFFSET: usize = 12;
/// A name's wire form, length octets and root label included, is at most
/// 255 octets (RFC 1035 section 2.3.4).
const MAX_NAME_OCTETS: usize = 255;

const SVC_PARAM_MANDATORY: u16 = 0;
const SVC_PARAM_ALPN: u16 = 1;
const SVC_PARAM_NO_DEFAULT_ALPN: u16 = 2;
const SVC_PARAM_PORT: u16 = 3;
const SVC_PARAM_IPV4HINT: u16 = 4;
const SVC_PARAM_IPV6HINT: u16 = 6;

/// Which resource record type a question asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsRecordType {
    /// `A`: IPv4 host address.
    A,
    /// `AAAA`: IPv6 host address.
    Aaaa,
    /// `HTTPS` (RFC 9460 Type 65): service binding for an `https` origin.
    Https,
}

impl DnsRecordType {
    const fn code(self) -> u16 {
        match self {
            Self::A => TYPE_A,
            Self::Aaaa => TYPE_AAAA,
            Self::Https => TYPE_HTTPS,
        }
    }
}

/// DNS header `RCODE` (RFC 1035 section 4.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsRcode {
    /// `0`: no error condition (`NOERROR`).
    NoError,
    /// `3`: queried domain name does not exist (`NXDOMAIN`).
    NxDomain,
    /// Any other response code (`FORMERR`, `SERVFAIL`, `NOTIMP`, `REFUSED`, ...).
    Other(u8),
}

/// Canonical uncompressed DNS domain name in wire format (`<= 255` octets,
/// terminating root `0` octet included).
///
/// Equality and hashing ignore ASCII case per RFC 1035 section 2.3.3.
#[derive(Clone, Copy)]
pub struct DnsWireName {
    octets: [u8; MAX_NAME_OCTETS],
    len: u8,
}

impl DnsWireName {
    /// Encodes `host` (dotted labels, with an optional single trailing dot)
    /// into uncompressed wire format.
    pub fn from_host(host: &str) -> Option<Self> {
        let host = host.strip_suffix('.').unwrap_or(host);
        let mut octets = [0u8; MAX_NAME_OCTETS];
        let mut offset = 0usize;
        for label in host.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            let end = offset + 1 + label.len();
            if end >= MAX_NAME_OCTETS {
                return None;
            }
            octets[offset] = label.len() as u8;
            octets[offset + 1..end].copy_from_slice(label.as_bytes());
            offset = end;
        }
        octets[offset] = 0;
        Some(Self {
            octets,
            len: (offset + 1) as u8,
        })
    }

    /// Encodes the RFC 9460 section 9.1 `QNAME` for an `https` origin:
    /// `host` when `port == 443`, and `_<port>._https.<host>` otherwise.
    pub fn https_qname(host: &str, port: u16) -> Option<Self> {
        let host_wire = Self::from_host(host)?;
        if port == HTTPS_DEFAULT_PORT {
            return Some(host_wire);
        }
        let mut port_digits = [0u8; 5];
        let digit_len = encode_u16_decimal(port, &mut port_digits);
        let port_label_len = 1 + digit_len;
        let https_label = b"_https";
        let prefix_len = (1 + port_label_len) + (1 + https_label.len());
        let host_slice = host_wire.as_wire();
        let total = prefix_len + host_slice.len();
        if total > MAX_NAME_OCTETS {
            return None;
        }
        let mut octets = [0u8; MAX_NAME_OCTETS];
        octets[0] = port_label_len as u8;
        octets[1] = b'_';
        octets[2..2 + digit_len].copy_from_slice(&port_digits[..digit_len]);
        let https_offset = 1 + port_label_len;
        octets[https_offset] = https_label.len() as u8;
        octets[https_offset + 1..prefix_len].copy_from_slice(https_label);
        octets[prefix_len..total].copy_from_slice(host_slice);
        Some(Self {
            octets,
            len: total as u8,
        })
    }

    /// Uncompressed wire octets including the terminating root `0` octet.
    pub fn as_wire(&self) -> &[u8] {
        &self.octets[..usize::from(self.len)]
    }

    /// Whether this name is the DNS root (`.`).
    pub const fn is_root(&self) -> bool {
        self.len == 1 && self.octets[0] == 0
    }

    /// Case-insensitive wire-name equality (RFC 1035 section 2.3.3).
    pub fn eq_ignore_ascii_case(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        let left = self.as_wire();
        let right = other.as_wire();
        let mut offset = 0usize;
        while offset < left.len() {
            let len = usize::from(left[offset]);
            if usize::from(right[offset]) != len {
                return false;
            }
            if len == 0 {
                return true;
            }
            let start = offset + 1;
            let end = start + len;
            if !left[start..end].eq_ignore_ascii_case(&right[start..end]) {
                return false;
            }
            offset = end;
        }
        false
    }

    fn from_wire(bytes: &[u8], offset: usize) -> Option<Self> {
        let mut octets = [0u8; MAX_NAME_OCTETS];
        let mut out = 0usize;
        for label in Labels::new(bytes, offset) {
            let label = label.ok()?;
            let end = out + 1 + label.len();
            if end >= MAX_NAME_OCTETS {
                return None;
            }
            octets[out] = label.len() as u8;
            octets[out + 1..end].copy_from_slice(label);
            out = end;
        }
        octets[out] = 0;
        Some(Self {
            octets,
            len: (out + 1) as u8,
        })
    }
}

impl PartialEq for DnsWireName {
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_ascii_case(other)
    }
}

impl Eq for DnsWireName {}

impl core::fmt::Debug for DnsWireName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "\"")?;
        if self.is_root() {
            return write!(f, ".\"");
        }
        let wire = self.as_wire();
        let mut offset = 0usize;
        let mut first = true;
        while offset < wire.len() {
            let len = usize::from(wire[offset]);
            if len == 0 {
                break;
            }
            if !first {
                write!(f, ".")?;
            }
            first = false;
            let label = &wire[offset + 1..offset + 1 + len];
            match core::str::from_utf8(label) {
                Ok(text) => write!(f, "{text}")?,
                Err(_) => write!(f, "{label:?}")?,
            }
            offset += 1 + len;
        }
        write!(f, "\"")
    }
}

/// Service parameters decoded from a usable `ServiceMode` `HTTPS` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsHttpsRecord<'a> {
    /// ALPN protocol identifiers from `SvcParamKey` 1, in wire order.
    pub alpn: ArrayVec<&'a str, DNS_MAX_ALPN_IDS>,
    /// Alternative port from `SvcParamKey` 3, when overridden.
    pub port: Option<u16>,
    /// Minimum TTL across the answer chain and matching `HTTPS` RRSet, in seconds.
    pub ttl_seconds: u32,
}

/// What a validated Type 65 (`HTTPS`) DNS response means for its question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsHttpsOutcome<'a> {
    /// A usable `ServiceMode` (`SvcPriority > 0`) record won.
    Service(DnsHttpsRecord<'a>),
    /// An `AliasMode` (`SvcPriority == 0`) record pointed at `target`, whose
    /// target records were not included in this packet and must be queried.
    Alias {
        target: DnsWireName,
        ttl_seconds: u32,
        /// Number of `CNAME` + `AliasMode` hops consumed inside this packet.
        hops: usize,
    },
    /// Definitive absence: `NXDOMAIN`, `NODATA`, `AliasMode` `.`, an
    /// incompatible/malformed RRSet, or an alias chain exceeding the bound.
    NoRecord,
    /// The server answered our question with a failure `RCODE` (such as
    /// `SERVFAIL` or `REFUSED`).
    ServerFailure(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    /// Every `A` and `AAAA` record in the answer section, in the order
    /// the server returned them. Both families land in one list because
    /// `wasi:sockets/ip-name-lookup` hands the guest a single address
    /// stream with no ordering guarantee.
    pub addresses: ArrayVec<IpAddress, DNS_MAX_ADDRESS_RECORDS>,
}

impl DnsMessage {
    pub fn ipv4_addresses(&self) -> impl Iterator<Item = Ipv4Address> + '_ {
        self.addresses.iter().filter_map(|address| match address {
            IpAddress::Ipv4(address) => Some(*address),
            IpAddress::Ipv6(_) => None,
        })
    }

    pub fn ipv6_addresses(&self) -> impl Iterator<Item = Ipv6Address> + '_ {
        self.addresses.iter().filter_map(|address| match address {
            IpAddress::Ipv6(address) => Some(*address),
            IpAddress::Ipv4(_) => None,
        })
    }
}

/// The question a response has to answer to be believed.
///
/// RFC 5452 section 9.1 and RFC 1035 section 7.3: a response is the
/// answer to a query only when its question section repeats the query's,
/// and only the records that question reaches are its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsQuery<'a> {
    /// The queried name, as written to [`DnsQuestionWriter`]: dotted
    /// labels without a trailing dot.
    pub name: &'a str,
    pub record: DnsRecordType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsResponse<'a> {
    bytes: &'a [u8],
}

impl<'a> DnsResponse<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        let flags = read_u16(bytes, 2)?;
        if flags & 0x8000 == 0 || flags & 0x7800 != 0 {
            return None;
        }
        Some(Self { bytes })
    }

    /// The transaction id, which selects the outstanding query this
    /// response claims to answer.
    pub fn id(self) -> u16 {
        // `parse` checked the header is present.
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    /// The response code carried in the DNS header.
    pub fn rcode(self) -> DnsRcode {
        match self.bytes[3] & 0x0f {
            0 => DnsRcode::NoError,
            3 => DnsRcode::NxDomain,
            other => DnsRcode::Other(other),
        }
    }

    /// The addresses this response gives for `query`, or `None` when it
    /// is not an answer to it.
    ///
    /// The question section must hold exactly one question whose name
    /// (compared case-insensitively, RFC 1035 section 2.3.3), type and
    /// class equal the query's. Only records of the queried type owned by
    /// the queried name, or by a name its `CNAME` chain reaches, are
    /// collected; records the forger had no reason to know the query for
    /// are not.
    pub fn message(self, query: DnsQuery<'_>) -> Option<DnsMessage> {
        if self.rcode() != DnsRcode::NoError {
            return None;
        }
        let bytes = self.bytes;
        let id = self.id();
        let question_count = read_u16(bytes, 4)?;
        let answer_count = read_u16(bytes, 6)?;
        if question_count != 1 {
            return None;
        }
        let question_name = QUESTION_OFFSET;
        let mut offset = skip_name(bytes, question_name)?;
        let question_type = read_u16(bytes, offset)?;
        let question_class = read_u16(bytes, offset.checked_add(2)?)?;
        offset = offset.checked_add(4)?;
        if question_type != query.record.code()
            || question_class != CLASS_IN
            || !name_equals_text(bytes, question_name, query.name)?
        {
            return None;
        }
        let answers_start = offset;

        // Offsets of the names whose records answer the question: the
        // question's own, then each `CNAME` target the chain reaches from
        // it. A name with a `CNAME` has no other data (RFC 2181 section
        // 10.1), so the chain is a path: each step looks for the `CNAME`
        // owned by its far end, wherever the response lists it, and the
        // walk stops at a name with none, at a name already on the path,
        // or at the chain limit.
        let mut owners: ArrayVec<usize, { DNS_MAX_CNAME_CHAIN + 1 }> = ArrayVec::new();
        owners.push(question_name);
        while !owners.is_full() {
            let end = owners[owners.len() - 1];
            let mut target = None;
            let mut cursor = answers_start;
            for _ in 0..answer_count {
                let record = read_record(bytes, &mut cursor)?;
                if record.class == CLASS_IN
                    && record.record_type == TYPE_CNAME
                    && names_equal(bytes, end, record.name)?
                {
                    target = Some(record.data_offset);
                    break;
                }
            }
            let Some(target) = target else {
                break;
            };
            if is_owner(bytes, &owners, target)? {
                break;
            }
            owners.push(target);
        }

        let mut addresses = ArrayVec::new();
        let mut cursor = answers_start;
        for _ in 0..answer_count {
            let record = read_record(bytes, &mut cursor)?;
            if record.class != CLASS_IN
                || record.record_type != query.record.code()
                || !is_owner(bytes, &owners, record.name)?
            {
                continue;
            }
            match (record.record_type, record.data) {
                (TYPE_A, data) if data.len() == 4 => {
                    let _ = addresses
                        .try_push(IpAddress::Ipv4(Ipv4Address::new(data.try_into().ok()?)));
                }
                (TYPE_AAAA, data) if data.len() == 16 => {
                    let _ = addresses
                        .try_push(IpAddress::Ipv6(Ipv6Address::new(data.try_into().ok()?)));
                }
                _ => {}
            }
        }

        Some(DnsMessage { id, addresses })
    }

    /// Evaluates this response against a Type 65 (`HTTPS`) question for
    /// `qname` serving `origin` (RFC 9460).
    ///
    /// Returns `None` when the packet does not echo `(qname, HTTPS, IN)` as
    /// its sole question or when any answer record header runs past the end
    /// of the datagram, so off-path or truncated packets are ignored rather
    /// than accepted.
    pub fn https_outcome(
        self,
        qname: &DnsWireName,
        origin: &DnsWireName,
    ) -> Option<DnsHttpsOutcome<'a>> {
        let bytes = self.bytes;
        let question_count = read_u16(bytes, 4)?;
        let answer_count = read_u16(bytes, 6)?;
        if question_count != 1 {
            return None;
        }
        let question_name = QUESTION_OFFSET;
        let mut offset = skip_name(bytes, question_name)?;
        let question_type = read_u16(bytes, offset)?;
        let question_class = read_u16(bytes, offset.checked_add(2)?)?;
        offset = offset.checked_add(4)?;
        if question_type != TYPE_HTTPS
            || question_class != CLASS_IN
            || !name_equals_wire(bytes, question_name, qname)?
        {
            return None;
        }
        let answers_start = offset;

        // Validate answer-section framing up front so a truncated packet
        // never masquerades as NODATA or NXDOMAIN.
        let mut framing_cursor = answers_start;
        for _ in 0..answer_count {
            read_record(bytes, &mut framing_cursor)?;
        }

        match self.rcode() {
            DnsRcode::NxDomain => return Some(DnsHttpsOutcome::NoRecord),
            DnsRcode::Other(code) => return Some(DnsHttpsOutcome::ServerFailure(code)),
            DnsRcode::NoError => {}
        }

        let mut owners: ArrayVec<usize, { DNS_MAX_CNAME_CHAIN + 1 }> = ArrayVec::new();
        owners.push(question_name);
        let mut chain_min_ttl: Option<u32> = None;

        loop {
            let end = owners[owners.len() - 1];

            let mut cname_step = None;
            let mut cursor = answers_start;
            for _ in 0..answer_count {
                let record = read_record(bytes, &mut cursor)?;
                if record.class == CLASS_IN
                    && record.record_type == TYPE_CNAME
                    && names_equal(bytes, end, record.name)?
                    && skip_name(bytes, record.data_offset)
                        == Some(record.data_offset + record.data.len())
                {
                    cname_step = Some((record.data_offset, record.ttl));
                    break;
                }
            }
            if let Some((target, ttl)) = cname_step {
                if owners.is_full() || is_owner(bytes, &owners, target)? {
                    return Some(DnsHttpsOutcome::NoRecord);
                }
                chain_min_ttl = Some(chain_min_ttl.map_or(ttl, |min| min.min(ttl)));
                owners.push(target);
                continue;
            }

            // RFC 9460 §2.4.1: an AliasMode (`SvcPriority == 0`) record in an
            // RRSet voids any ServiceMode records beside it.
            let mut alias_step = None;
            let mut cursor = answers_start;
            for _ in 0..answer_count {
                let record = read_record(bytes, &mut cursor)?;
                if record.class != CLASS_IN
                    || record.record_type != TYPE_HTTPS
                    || !names_equal(bytes, end, record.name)?
                {
                    continue;
                }
                if let Some(ParsedHttpsRdata::Alias { is_root }) = parse_https_rdata(record.data) {
                    alias_step = Some((is_root, record.data_offset + 2, record.ttl));
                    break;
                }
            }
            if let Some((is_root, target_offset, ttl)) = alias_step {
                // RFC 9460 §2.5.1: `.` in AliasMode declares the service unavailable.
                if is_root {
                    return Some(DnsHttpsOutcome::NoRecord);
                }
                if owners.is_full() || is_owner(bytes, &owners, target_offset)? {
                    return Some(DnsHttpsOutcome::NoRecord);
                }
                let next_ttl = chain_min_ttl.map_or(ttl, |min| min.min(ttl));
                if has_cname_or_https_for(bytes, answers_start, answer_count, target_offset)? {
                    chain_min_ttl = Some(next_ttl);
                    owners.push(target_offset);
                    continue;
                }
                let target = DnsWireName::from_wire(bytes, target_offset)?;
                return Some(DnsHttpsOutcome::Alias {
                    target,
                    ttl_seconds: next_ttl,
                    hops: owners.len(),
                });
            }

            break;
        }

        let end = owners[owners.len() - 1];
        let mut best: Option<SelectedHttpsService<'a>> = None;
        let mut rrset_min_ttl: Option<u32> = None;
        let mut cursor = answers_start;
        for _ in 0..answer_count {
            let record = read_record(bytes, &mut cursor)?;
            if record.class != CLASS_IN
                || record.record_type != TYPE_HTTPS
                || !names_equal(bytes, end, record.name)?
            {
                continue;
            }
            let Some(ParsedHttpsRdata::Service {
                priority,
                compatible,
                alpn_wire,
                port,
            }) = parse_https_rdata(record.data)
            else {
                continue;
            };
            rrset_min_ttl = Some(rrset_min_ttl.map_or(record.ttl, |min| min.min(record.ttl)));
            // `HttpsRecord` carries no alternative target host, so only
            // endpoints on `.` or the queried/aliased host itself are usable
            // (matching `zenwave`'s same-host origin security rule).
            if !compatible || !service_target_matches(bytes, record.data_offset + 2, end, origin)? {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|current| priority < current.priority)
            {
                best = Some(SelectedHttpsService {
                    priority,
                    alpn_wire,
                    port,
                });
            }
        }

        let Some(best) = best else {
            return Some(DnsHttpsOutcome::NoRecord);
        };
        let alpn = match best.alpn_wire {
            Some(wire) => collect_alpn_ids(wire)?,
            None => ArrayVec::new(),
        };
        let ttl_seconds = match (chain_min_ttl, rrset_min_ttl) {
            (Some(chain_ttl), Some(rr_ttl)) => chain_ttl.min(rr_ttl),
            (_, Some(rr_ttl)) => rr_ttl,
            _ => 0,
        };
        Some(DnsHttpsOutcome::Service(DnsHttpsRecord {
            alpn,
            port: best.port,
            ttl_seconds,
        }))
    }
}

pub struct DnsQuestionWriter<'a> {
    output: &'a mut [u8],
}

impl<'a> DnsQuestionWriter<'a> {
    pub fn new(output: &'a mut [u8]) -> Self {
        Self { output }
    }

    /// Writes an `A` question. Kept as a named entry point because the
    /// IPv4-only paths (DHCP-configured resolvers, ICMP echo target
    /// resolution) ask for nothing else.
    pub fn write_a_query(&mut self, id: u16, name: &str) -> Option<usize> {
        self.write_query(id, name, DnsRecordType::A)
    }

    /// Writes an `AAAA` question.
    pub fn write_aaaa_query(&mut self, id: u16, name: &str) -> Option<usize> {
        self.write_query(id, name, DnsRecordType::Aaaa)
    }

    /// Writes an RFC 9460 Type 65 (`HTTPS`) question for `host:port`.
    pub fn write_https_query(&mut self, id: u16, host: &str, port: u16) -> Option<usize> {
        let qname = DnsWireName::https_qname(host, port)?;
        self.write_wire_query(id, &qname, DnsRecordType::Https)
    }

    /// Writes a question whose `QNAME` is already in canonical uncompressed
    /// wire format.
    pub fn write_wire_query(
        &mut self,
        id: u16,
        qname: &DnsWireName,
        record: DnsRecordType,
    ) -> Option<usize> {
        let wire = qname.as_wire();
        let total = QUESTION_OFFSET.checked_add(wire.len())?.checked_add(4)?;
        if self.output.len() < total {
            return None;
        }
        self.output[..QUESTION_OFFSET].fill(0);
        write_u16(self.output, 0, id)?;
        write_u16(self.output, 2, 0x0100)?;
        write_u16(self.output, 4, 1)?;
        let qtype_offset = QUESTION_OFFSET + wire.len();
        self.output[QUESTION_OFFSET..qtype_offset].copy_from_slice(wire);
        write_u16(self.output, qtype_offset, record.code())?;
        write_u16(self.output, qtype_offset + 2, CLASS_IN)?;
        Some(total)
    }

    pub fn write_query(&mut self, id: u16, name: &str, record: DnsRecordType) -> Option<usize> {
        if self.output.len() < 12 {
            return None;
        }
        self.output[..12].fill(0);
        write_u16(self.output, 0, id)?;
        write_u16(self.output, 2, 0x0100)?;
        write_u16(self.output, 4, 1)?;
        let mut offset = 12usize;
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            let end = offset.checked_add(1 + label.len())?;
            if self.output.len() < end {
                return None;
            }
            self.output[offset] = label.len() as u8;
            self.output[offset + 1..end].copy_from_slice(label.as_bytes());
            offset = end;
        }
        // The labels and the root octet below are the name's wire form.
        if offset - QUESTION_OFFSET + 1 > MAX_NAME_OCTETS {
            return None;
        }
        if self.output.len() < offset + 5 {
            return None;
        }
        self.output[offset] = 0;
        offset += 1;
        write_u16(self.output, offset, record.code())?;
        offset += 2;
        write_u16(self.output, offset, CLASS_IN)?;
        offset += 2;
        Some(offset)
    }
}

struct SelectedHttpsService<'a> {
    priority: u16,
    alpn_wire: Option<&'a [u8]>,
    port: Option<u16>,
}

enum ParsedHttpsRdata<'a> {
    Alias {
        is_root: bool,
    },
    Service {
        priority: u16,
        compatible: bool,
        alpn_wire: Option<&'a [u8]>,
        port: Option<u16>,
    },
}

/// Decodes one RFC 9460 Type 65 `RDATA` payload.
///
/// Returns `None` when the record violates RFC 9460 wire syntax: truncated
/// fields, compressed or invalid `TargetName`, non-increasing or duplicate
/// `SvcParamKey`s, malformed `mandatory` / `alpn` / `no-default-alpn` / `port`
/// / address-hint values, or a `mandatory` key absent from `SvcParams`.
fn parse_https_rdata<'a>(data: &'a [u8]) -> Option<ParsedHttpsRdata<'a>> {
    let priority = read_u16(data, 0)?;
    let target_wire = data.get(2..)?;
    let target_len = skip_uncompressed_name(target_wire)?;
    let is_root = target_len == 1;
    let mut params = data.get(2 + target_len..)?;

    if priority == 0 {
        // RFC 9460 §2.4.2: AliasMode ignores any SvcParams that are present,
        // while §2.2 still requires any trailing SvcParams to frame cleanly
        // in strictly increasing key order.
        let mut prev_key: Option<u16> = None;
        while !params.is_empty() {
            let key = read_u16(params, 0)?;
            let value_len = usize::from(read_u16(params, 2)?);
            let value_end = 4usize.checked_add(value_len)?;
            params = params.get(value_end..)?;
            if let Some(prev) = prev_key
                && key <= prev
            {
                return None;
            }
            prev_key = Some(key);
        }
        return Some(ParsedHttpsRdata::Alias { is_root });
    }

    let mut prev_key: Option<u16> = None;
    let mut mandatory_supported_mask: u8 = 0;
    let mut seen_supported_mask: u8 = 0;
    let mut unsupported_mandatory_key: Option<u16> = None;
    let mut unsupported_mandatory_present = true;
    let mut alpn_wire: Option<&'a [u8]> = None;
    let mut port: Option<u16> = None;

    // If `mandatory` lists keys outside `{1, 2, 3}`, we also verify every such
    // key actually appears in `SvcParams` (RFC 9460 §7 syntax) while marking
    // the RR incompatible (RFC 9460 §8).
    let mut mandatory_list: &[u8] = &[];

    while !params.is_empty() {
        let key = read_u16(params, 0)?;
        let value_len = usize::from(read_u16(params, 2)?);
        let value_end = 4usize.checked_add(value_len)?;
        let value = params.get(4..value_end)?;
        params = &params[value_end..];

        if let Some(prev) = prev_key
            && key <= prev
        {
            return None;
        }
        prev_key = Some(key);

        match key {
            SVC_PARAM_MANDATORY => {
                if value.is_empty() || !value.len().is_multiple_of(2) {
                    return None;
                }
                let mut prev_req: Option<u16> = None;
                let mut offset = 0usize;
                while offset < value.len() {
                    let req = u16::from_be_bytes([value[offset], value[offset + 1]]);
                    if req == SVC_PARAM_MANDATORY {
                        return None;
                    }
                    if let Some(prev) = prev_req
                        && req <= prev
                    {
                        return None;
                    }
                    prev_req = Some(req);
                    match req {
                        SVC_PARAM_ALPN => mandatory_supported_mask |= 1 << 1,
                        SVC_PARAM_NO_DEFAULT_ALPN => mandatory_supported_mask |= 1 << 2,
                        SVC_PARAM_PORT => mandatory_supported_mask |= 1 << 3,
                        other => {
                            unsupported_mandatory_key.get_or_insert(other);
                        }
                    }
                    offset += 2;
                }
                mandatory_list = value;
            }
            SVC_PARAM_ALPN => {
                seen_supported_mask |= 1 << 1;
                if !validate_alpn_wire(value) {
                    return None;
                }
                alpn_wire = Some(value);
            }
            SVC_PARAM_NO_DEFAULT_ALPN => {
                seen_supported_mask |= 1 << 2;
                if !value.is_empty() {
                    return None;
                }
            }
            SVC_PARAM_PORT => {
                seen_supported_mask |= 1 << 3;
                if value.len() != 2 {
                    return None;
                }
                port = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            SVC_PARAM_IPV4HINT if value.is_empty() || !value.len().is_multiple_of(4) => {
                return None;
            }
            SVC_PARAM_IPV6HINT if value.is_empty() || !value.len().is_multiple_of(16) => {
                return None;
            }
            _ => {}
        }
    }

    if (mandatory_supported_mask & seen_supported_mask) != mandatory_supported_mask {
        return None;
    }

    // Verify any unsupported mandatory keys were at least present in SvcParams
    // so a missing mandatory key is classified as malformed (`None`) per §7.
    if unsupported_mandatory_key.is_some() {
        let after_mandatory = data.get(2 + target_len + 4 + mandatory_list.len()..)?;
        let mut req_offset = 0usize;
        while req_offset < mandatory_list.len() {
            let req =
                u16::from_be_bytes([mandatory_list[req_offset], mandatory_list[req_offset + 1]]);
            if !svc_params_contain_key(after_mandatory, req) {
                return None;
            }
            req_offset += 2;
        }
        unsupported_mandatory_present = false;
    }

    let no_default_without_alpn =
        (seen_supported_mask & (1 << 2)) != 0 && (seen_supported_mask & (1 << 1)) == 0;
    let compatible = unsupported_mandatory_present && !no_default_without_alpn;

    Some(ParsedHttpsRdata::Service {
        priority,
        compatible,
        alpn_wire,
        port,
    })
}

fn validate_alpn_wire(value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut cursor = 0usize;
    while cursor < value.len() {
        let id_len = usize::from(value[cursor]);
        if id_len == 0 {
            return false;
        }
        let id_end = cursor + 1 + id_len;
        let Some(id_bytes) = value.get(cursor + 1..id_end) else {
            return false;
        };
        if core::str::from_utf8(id_bytes).is_err() {
            return false;
        }
        cursor = id_end;
    }
    true
}

fn collect_alpn_ids(value: &[u8]) -> Option<ArrayVec<&str, DNS_MAX_ALPN_IDS>> {
    let mut alpn = ArrayVec::new();
    let mut cursor = 0usize;
    while cursor < value.len() {
        let id_len = usize::from(*value.get(cursor)?);
        if id_len == 0 {
            return None;
        }
        let id_end = cursor + 1 + id_len;
        let id_str = core::str::from_utf8(value.get(cursor + 1..id_end)?).ok()?;
        let _ = alpn.try_push(id_str);
        cursor = id_end;
    }
    Some(alpn)
}

fn svc_params_contain_key(mut params: &[u8], wanted: u16) -> bool {
    while let Some(key) = read_u16(params, 0) {
        let Some(len) = read_u16(params, 2) else {
            return false;
        };
        if key == wanted {
            return true;
        }
        if key > wanted {
            return false;
        }
        let Some(rest) = params.get(4 + usize::from(len)..) else {
            return false;
        };
        params = rest;
    }
    false
}

/// Validates an uncompressed wire name at the start of `data` (RFC 9460 §2.2,
/// RFC 3597 §4) and returns its wire length, root octet included.
fn skip_uncompressed_name(data: &[u8]) -> Option<usize> {
    let mut offset = 0usize;
    loop {
        let &len = data.get(offset)?;
        if len == 0 {
            let total = offset + 1;
            return (total <= MAX_NAME_OCTETS).then_some(total);
        }
        if len > 63 {
            return None;
        }
        let next = offset + 1 + usize::from(len);
        if next > data.len() || next >= MAX_NAME_OCTETS {
            return None;
        }
        offset = next;
    }
}

fn has_cname_or_https_for(
    bytes: &[u8],
    answers_start: usize,
    answer_count: u16,
    owner: usize,
) -> Option<bool> {
    let mut cursor = answers_start;
    for _ in 0..answer_count {
        let record = read_record(bytes, &mut cursor)?;
        if record.class == CLASS_IN
            && (record.record_type == TYPE_CNAME || record.record_type == TYPE_HTTPS)
            && names_equal(bytes, owner, record.name)?
        {
            return Some(true);
        }
    }
    Some(false)
}

/// Whether `target_offset` (a validated uncompressed `ServiceMode`
/// `TargetName`) names `.`, `origin`, `owner`, or `owner` stripped of a
/// leading `_<port>._https.` service prefix.
fn service_target_matches(
    bytes: &[u8],
    target_offset: usize,
    owner_offset: usize,
    origin: &DnsWireName,
) -> Option<bool> {
    if bytes.get(target_offset).copied() == Some(0) {
        return Some(true);
    }
    if name_equals_wire(bytes, target_offset, origin)?
        || names_equal(bytes, target_offset, owner_offset)?
    {
        return Some(true);
    }
    let mut owner_labels = Labels::new(bytes, owner_offset);
    let Some(Ok(first)) = owner_labels.next() else {
        return Some(false);
    };
    let Some(Ok(second)) = owner_labels.next() else {
        return Some(false);
    };
    let is_port_prefix = first.first() == Some(&b'_')
        && (2..=6).contains(&first.len())
        && first[1..].iter().all(u8::is_ascii_digit)
        && second.eq_ignore_ascii_case(b"_https");
    if !is_port_prefix {
        return Some(false);
    }
    let mut target_labels = Labels::new(bytes, target_offset);
    loop {
        match (target_labels.next(), owner_labels.next()) {
            (None, None) => return Some(true),
            (Some(Ok(left)), Some(Ok(right))) => {
                if !left.eq_ignore_ascii_case(right) {
                    return Some(false);
                }
            }
            (Some(Err(MalformedName)), _) | (_, Some(Err(MalformedName))) => return None,
            (Some(Ok(_)), None) | (None, Some(Ok(_))) => return Some(false),
        }
    }
}

fn encode_u16_decimal(mut value: u16, out: &mut [u8; 5]) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut scratch = [0u8; 5];
    let mut count = 0usize;
    while value > 0 {
        scratch[count] = b'0' + (value % 10) as u8;
        value /= 10;
        count += 1;
    }
    for idx in 0..count {
        out[idx] = scratch[count - 1 - idx];
    }
    count
}

/// Where the name at `offset` ends in the message: past its root label or
/// its first compression pointer. `None` when the name does not decode.
fn skip_name(bytes: &[u8], offset: usize) -> Option<usize> {
    let mut labels = Labels::new(bytes, offset);
    for label in labels.by_ref() {
        label.ok()?;
    }
    labels.end_in_place
}

/// One resource record, located in the message rather than copied out of
/// it: its owner name and its `RDATA` are offsets or slices of the
/// datagram.
struct Record<'a> {
    /// Offset of the owner name.
    name: usize,
    record_type: u16,
    class: u16,
    ttl: u32,
    /// Offset of the `RDATA`, which for a `CNAME` is the target name.
    data_offset: usize,
    data: &'a [u8],
}

/// Reads the record at `*cursor` and moves the cursor past it.
fn read_record<'a>(bytes: &'a [u8], cursor: &mut usize) -> Option<Record<'a>> {
    let name = *cursor;
    let mut offset = skip_name(bytes, name)?;
    let record_type = read_u16(bytes, offset)?;
    let class = read_u16(bytes, offset.checked_add(2)?)?;
    let ttl = read_u32(bytes, offset.checked_add(4)?)?;
    let data_len = usize::from(read_u16(bytes, offset.checked_add(8)?)?);
    offset = offset.checked_add(10)?;
    let data_end = offset.checked_add(data_len)?;
    let data = bytes.get(offset..data_end)?;
    *cursor = data_end;
    Some(Record {
        name,
        record_type,
        class,
        ttl,
        data_offset: offset,
        data,
    })
}

/// A name that does not decode: a label running past the message, a
/// reserved label type, a compression pointer that does not point back
/// past the last one, or more than [`MAX_NAME_OCTETS`].
struct MalformedName;

/// The labels of the name at `offset`, following compression pointers.
///
/// A pointer names a prior occurrence of the name's suffix (RFC 1035
/// section 4.1.4), so each pointer must land before the one followed
/// last, or before the name itself for the first; a chain of them then
/// cannot loop, and with the octet limit a name decodes in a bounded
/// number of steps however the message is built.
struct Labels<'a> {
    bytes: &'a [u8],
    offset: usize,
    /// Every compression pointer must land below this offset.
    pointer_limit: usize,
    /// Wire octets decoded so far, length octets included.
    octets: usize,
    /// Where the name ends in the message, once the decoder has passed
    /// its root label or its first pointer.
    end_in_place: Option<usize>,
    finished: bool,
}

impl<'a> Labels<'a> {
    fn new(bytes: &'a [u8], offset: usize) -> Self {
        Self {
            bytes,
            offset,
            pointer_limit: offset,
            octets: 0,
            end_in_place: None,
            finished: false,
        }
    }

    fn fail(&mut self) -> Option<Result<&'a [u8], MalformedName>> {
        self.finished = true;
        Some(Err(MalformedName))
    }
}

impl<'a> Iterator for Labels<'a> {
    type Item = Result<&'a [u8], MalformedName>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        loop {
            let Some(&len) = self.bytes.get(self.offset) else {
                return self.fail();
            };
            match len & 0xc0 {
                0xc0 => {
                    let Some(pointer) = read_u16(self.bytes, self.offset) else {
                        return self.fail();
                    };
                    let target = usize::from(pointer & 0x3fff);
                    if target >= self.pointer_limit {
                        return self.fail();
                    }
                    self.end_in_place.get_or_insert(self.offset + 2);
                    self.pointer_limit = target;
                    self.offset = target;
                }
                0 if len == 0 => {
                    self.octets += 1;
                    if self.octets > MAX_NAME_OCTETS {
                        return self.fail();
                    }
                    self.end_in_place.get_or_insert(self.offset + 1);
                    self.finished = true;
                    return None;
                }
                0 => {
                    let start = self.offset + 1;
                    let end = start + usize::from(len);
                    self.octets += 1 + usize::from(len);
                    if self.octets > MAX_NAME_OCTETS {
                        return self.fail();
                    }
                    let Some(label) = self.bytes.get(start..end) else {
                        return self.fail();
                    };
                    self.offset = end;
                    return Some(Ok(label));
                }
                _ => return self.fail(),
            }
        }
    }
}

/// Whether the names at two offsets are the same name, labels compared
/// without regard to ASCII case. `None` when either does not decode.
fn names_equal(bytes: &[u8], left: usize, right: usize) -> Option<bool> {
    let mut left = Labels::new(bytes, left);
    let mut right = Labels::new(bytes, right);
    loop {
        match (left.next(), right.next()) {
            (None, None) => return Some(true),
            (Some(Ok(left)), Some(Ok(right))) => {
                if !left.eq_ignore_ascii_case(right) {
                    return Some(false);
                }
            }
            (Some(Err(MalformedName)), _) | (_, Some(Err(MalformedName))) => return None,
            (Some(Ok(_)), None) | (None, Some(Ok(_))) => return Some(false),
        }
    }
}

/// Whether the name at `offset` is `text` (dotted labels), ignoring
/// ASCII case. `None` when the name does not decode.
fn name_equals_text(bytes: &[u8], offset: usize, text: &str) -> Option<bool> {
    let mut wire = Labels::new(bytes, offset);
    let mut text = text.split('.');
    loop {
        match (wire.next(), text.next()) {
            (None, None) => return Some(true),
            (Some(Ok(wire)), Some(text)) => {
                if !wire.eq_ignore_ascii_case(text.as_bytes()) {
                    return Some(false);
                }
            }
            (Some(Err(MalformedName)), _) => return None,
            (Some(Ok(_)), None) | (None, Some(_)) => return Some(false),
        }
    }
}

/// Whether the name at `offset` equals `expected`, ignoring ASCII case.
/// `None` when the packet's name does not decode.
fn name_equals_wire(bytes: &[u8], offset: usize, expected: &DnsWireName) -> Option<bool> {
    let mut wire = Labels::new(bytes, offset);
    let expected = expected.as_wire();
    let mut exp_offset = 0usize;
    loop {
        let exp_len = usize::from(*expected.get(exp_offset)?);
        let next_exp = if exp_len == 0 {
            None
        } else {
            let label = expected.get(exp_offset + 1..exp_offset + 1 + exp_len)?;
            exp_offset += 1 + exp_len;
            Some(label)
        };
        match (wire.next(), next_exp) {
            (None, None) => return Some(true),
            (Some(Ok(wire_label)), Some(exp_label)) => {
                if !wire_label.eq_ignore_ascii_case(exp_label) {
                    return Some(false);
                }
            }
            (Some(Err(MalformedName)), _) => return None,
            (Some(Ok(_)), None) | (None, Some(_)) => return Some(false),
        }
    }
}

/// Whether the name at `name` is one of the `owners`. `None` when a name
/// does not decode.
fn is_owner(bytes: &[u8], owners: &[usize], name: usize) -> Option<bool> {
    for &owner in owners {
        if names_equal(bytes, owner, name)? {
            return Some(true);
        }
    }
    Some(false)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    Some(u16::from_be_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_be_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Option<()> {
    let end = offset.checked_add(2)?;
    bytes
        .get_mut(offset..end)?
        .copy_from_slice(&value.to_be_bytes());
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_A: DnsQuery<'static> = DnsQuery {
        name: "example.com",
        record: DnsRecordType::A,
    };
    const EXAMPLE_AAAA: DnsQuery<'static> = DnsQuery {
        name: "example.com",
        record: DnsRecordType::Aaaa,
    };

    /// Where an answer record's owner name comes from.
    enum Owner<'a> {
        /// A compression pointer to the question's name, the way real
        /// resolvers write it.
        Question,
        /// A name written out in full.
        Name(&'a str),
    }

    fn push_name(bytes: &mut alloc::vec::Vec<u8>, name: &str) {
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
    }

    fn push_record(
        bytes: &mut alloc::vec::Vec<u8>,
        owner: &Owner<'_>,
        record_type: u16,
        data: &[u8],
    ) {
        match owner {
            Owner::Question => bytes.extend_from_slice(&[0xc0, 0x0c]),
            Owner::Name(name) => push_name(bytes, name),
        }
        bytes.extend_from_slice(&record_type.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        bytes.extend_from_slice(&60u32.to_be_bytes());
        bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(data);
    }

    /// A response whose question is `name` / `question_type` / `class`.
    fn response_for(
        name: &str,
        question_type: u16,
        class: u16,
        answers: &[(Owner<'_>, u16, alloc::vec::Vec<u8>)],
    ) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec::Vec::new();
        bytes.extend_from_slice(&0x1234u16.to_be_bytes());
        bytes.extend_from_slice(&0x8180u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        push_name(&mut bytes, name);
        bytes.extend_from_slice(&question_type.to_be_bytes());
        bytes.extend_from_slice(&class.to_be_bytes());
        for (owner, record_type, data) in answers {
            push_record(&mut bytes, owner, *record_type, data);
        }
        bytes
    }

    fn wire_name(name: &str) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec::Vec::new();
        push_name(&mut bytes, name);
        bytes
    }

    fn response_with(answers: &[(u16, &[u8])]) -> alloc::vec::Vec<u8> {
        let answers: alloc::vec::Vec<_> = answers
            .iter()
            .map(|(record_type, data)| (Owner::Question, *record_type, data.to_vec()))
            .collect();
        response_for("example.com", TYPE_A, CLASS_IN, &answers)
    }

    fn parse(bytes: &[u8], query: DnsQuery<'_>) -> Option<DnsMessage> {
        DnsResponse::parse(bytes).and_then(|response| response.message(query))
    }

    #[test]
    fn aaaa_query_differs_from_a_query_only_in_the_question_type() {
        let mut a = [0u8; 64];
        let mut aaaa = [0u8; 64];
        let a_len = DnsQuestionWriter::new(&mut a)
            .write_a_query(7, "example.com")
            .expect("A query should encode");
        let aaaa_len = DnsQuestionWriter::new(&mut aaaa)
            .write_aaaa_query(7, "example.com")
            .expect("AAAA query should encode");

        assert_eq!(a_len, aaaa_len);
        assert_eq!(&a[..a_len - 4], &aaaa[..aaaa_len - 4]);
        assert_eq!(u16::from_be_bytes([a[a_len - 4], a[a_len - 3]]), TYPE_A);
        assert_eq!(
            u16::from_be_bytes([aaaa[aaaa_len - 4], aaaa[aaaa_len - 3]]),
            TYPE_AAAA
        );
        assert_eq!(
            u16::from_be_bytes([aaaa[aaaa_len - 2], aaaa[aaaa_len - 1]]),
            CLASS_IN
        );
    }

    const EXAMPLE_V6: [u8; 16] = [
        0x26, 0x06, 0x28, 0x00, 0x02, 0x1f, 0xcb, 0x07, 0x68, 0x20, 0x80, 0xda, 0x00, 0xaf, 0x6b,
        0x08,
    ];

    #[test]
    fn response_collects_the_queried_family() {
        let bytes = response_with(&[(TYPE_A, &[93, 184, 215, 14])]);
        let message = parse(&bytes, EXAMPLE_A).expect("response should parse");

        assert_eq!(message.id, 0x1234);
        assert_eq!(
            message.ipv4_addresses().collect::<alloc::vec::Vec<_>>(),
            alloc::vec![Ipv4Address::new([93, 184, 215, 14])]
        );

        let bytes = response_for(
            "example.com",
            TYPE_AAAA,
            CLASS_IN,
            &[(Owner::Question, TYPE_AAAA, EXAMPLE_V6.to_vec())],
        );
        let message = parse(&bytes, EXAMPLE_AAAA).expect("response should parse");
        assert_eq!(
            message.ipv6_addresses().collect::<alloc::vec::Vec<_>>(),
            alloc::vec![Ipv6Address::new(EXAMPLE_V6)]
        );
    }

    #[test]
    fn records_of_another_type_than_the_question_are_not_used() {
        let bytes = response_with(&[(TYPE_A, &[93, 184, 215, 14]), (TYPE_AAAA, &EXAMPLE_V6)]);
        let message = parse(&bytes, EXAMPLE_A).expect("response should parse");

        assert_eq!(message.addresses.len(), 1);
    }

    #[test]
    fn answer_for_another_name_is_rejected() {
        let bytes = response_for(
            "attacker.example",
            TYPE_A,
            CLASS_IN,
            &[(Owner::Question, TYPE_A, alloc::vec![6, 6, 6, 6])],
        );

        assert_eq!(parse(&bytes, EXAMPLE_A), None);
    }

    #[test]
    fn answer_for_another_type_or_class_is_rejected() {
        let wrong_type = response_for(
            "example.com",
            TYPE_AAAA,
            CLASS_IN,
            &[(Owner::Question, TYPE_AAAA, EXAMPLE_V6.to_vec())],
        );
        assert_eq!(parse(&wrong_type, EXAMPLE_A), None);

        let wrong_class = response_for(
            "example.com",
            TYPE_A,
            3,
            &[(Owner::Question, TYPE_A, alloc::vec![6, 6, 6, 6])],
        );
        assert_eq!(parse(&wrong_class, EXAMPLE_A), None);
    }

    #[test]
    fn response_without_exactly_one_question_is_rejected() {
        let mut bytes = response_with(&[(TYPE_A, &[1, 2, 3, 4])]);
        bytes[5] = 0;
        assert_eq!(parse(&bytes, EXAMPLE_A), None);
    }

    #[test]
    fn question_name_matches_without_regard_to_case() {
        // A resolver that applies 0x20 case randomisation echoes the
        // question in the case it was sent; RFC 1035 section 2.3.3 makes
        // the comparison case-insensitive either way.
        let bytes = response_for(
            "ExAmPlE.CoM",
            TYPE_A,
            CLASS_IN,
            &[(Owner::Question, TYPE_A, alloc::vec![1, 2, 3, 4])],
        );

        assert_eq!(
            parse(&bytes, EXAMPLE_A)
                .expect("case differences are not mismatches")
                .addresses
                .len(),
            1
        );
    }

    #[test]
    fn records_owned_by_unrelated_names_are_dropped() {
        let bytes = response_for(
            "example.com",
            TYPE_A,
            CLASS_IN,
            &[
                (
                    Owner::Name("attacker.example"),
                    TYPE_A,
                    alloc::vec![6, 6, 6, 6],
                ),
                (Owner::Question, TYPE_A, alloc::vec![1, 2, 3, 4]),
            ],
        );
        let message = parse(&bytes, EXAMPLE_A).expect("response should parse");

        assert_eq!(
            message.addresses.as_slice(),
            &[IpAddress::Ipv4(Ipv4Address::new([1, 2, 3, 4]))]
        );
    }

    #[test]
    fn records_owned_by_the_cname_chain_are_used_in_any_order() {
        // example.com -> www.example.net -> edge.example.org, listed with
        // the far link first and the address owned by the chain's end.
        let bytes = response_for(
            "example.com",
            TYPE_A,
            CLASS_IN,
            &[
                (
                    Owner::Name("EDGE.example.org"),
                    TYPE_A,
                    alloc::vec![1, 2, 3, 4],
                ),
                (
                    Owner::Name("www.example.net"),
                    TYPE_CNAME,
                    wire_name("edge.example.org"),
                ),
                (Owner::Question, TYPE_CNAME, wire_name("www.example.net")),
                (
                    Owner::Name("unrelated.example"),
                    TYPE_A,
                    alloc::vec![6, 6, 6, 6],
                ),
            ],
        );
        let message = parse(&bytes, EXAMPLE_A).expect("response should parse");

        assert_eq!(
            message.addresses.as_slice(),
            &[IpAddress::Ipv4(Ipv4Address::new([1, 2, 3, 4]))]
        );
    }

    #[test]
    fn a_cname_owned_by_an_unrelated_name_extends_nothing() {
        let bytes = response_for(
            "example.com",
            TYPE_A,
            CLASS_IN,
            &[
                (
                    Owner::Name("attacker.example"),
                    TYPE_CNAME,
                    wire_name("victim.example"),
                ),
                (
                    Owner::Name("victim.example"),
                    TYPE_A,
                    alloc::vec![6, 6, 6, 6],
                ),
            ],
        );
        let message = parse(&bytes, EXAMPLE_A).expect("response should parse");

        assert!(message.addresses.is_empty());
    }

    #[test]
    fn a_cname_chain_past_the_limit_is_not_followed() {
        // example.com -> l1.example -> ... -> l12.example: one link more
        // than the limit, so l11.example is the last name trusted.
        let links: alloc::vec::Vec<alloc::string::String> = (1..=DNS_MAX_CNAME_CHAIN + 1)
            .map(|link| alloc::format!("l{link}.example"))
            .collect();
        let mut answers = alloc::vec![(Owner::Question, TYPE_CNAME, wire_name(&links[0]))];
        for pair in links.windows(2) {
            answers.push((Owner::Name(&pair[0]), TYPE_CNAME, wire_name(&pair[1])));
        }
        answers.push((
            Owner::Name(&links[DNS_MAX_CNAME_CHAIN - 1]),
            TYPE_A,
            alloc::vec![1, 2, 3, 4],
        ));
        answers.push((
            Owner::Name(&links[DNS_MAX_CNAME_CHAIN]),
            TYPE_A,
            alloc::vec![6, 6, 6, 6],
        ));
        let bytes = response_for("example.com", TYPE_A, CLASS_IN, &answers);
        let message = parse(&bytes, EXAMPLE_A).expect("response should parse");

        assert_eq!(
            message.addresses.as_slice(),
            &[IpAddress::Ipv4(Ipv4Address::new([1, 2, 3, 4]))]
        );
    }

    #[test]
    fn a_cname_loop_ends_the_chain() {
        let bytes = response_for(
            "example.com",
            TYPE_A,
            CLASS_IN,
            &[
                (Owner::Question, TYPE_CNAME, wire_name("alias.example")),
                (
                    Owner::Name("alias.example"),
                    TYPE_CNAME,
                    wire_name("example.com"),
                ),
                (
                    Owner::Name("alias.example"),
                    TYPE_A,
                    alloc::vec![1, 2, 3, 4],
                ),
            ],
        );
        let message = parse(&bytes, EXAMPLE_A).expect("response should parse");

        assert_eq!(
            message.addresses.as_slice(),
            &[IpAddress::Ipv4(Ipv4Address::new([1, 2, 3, 4]))]
        );
    }

    #[test]
    fn a_compression_pointer_that_does_not_point_back_rejects_the_response() {
        let mut bytes = response_for("example.com", TYPE_A, CLASS_IN, &[]);
        bytes[7] = 1;
        // The answer's owner is the label `a` followed by a pointer back
        // to that label: a loop a decoder would follow forever.
        let owner = u16::try_from(bytes.len()).expect("test message fits a pointer");
        bytes.extend_from_slice(&[1, b'a']);
        bytes.extend_from_slice(&(0xc000 | owner).to_be_bytes());
        bytes.extend_from_slice(&TYPE_A.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        bytes.extend_from_slice(&60u32.to_be_bytes());
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&[6, 6, 6, 6]);

        assert_eq!(parse(&bytes, EXAMPLE_A), None);
    }

    #[test]
    fn a_name_longer_than_255_octets_rejects_the_response() {
        // Four 63-octet labels and the root are 257 octets on the wire.
        let label = "a".repeat(63);
        let name = [label.as_str(); 4].join(".");
        let bytes = response_for(
            &name,
            TYPE_A,
            CLASS_IN,
            &[(Owner::Question, TYPE_A, alloc::vec![6, 6, 6, 6])],
        );
        let query = DnsQuery {
            name: &name,
            record: DnsRecordType::A,
        };

        assert_eq!(parse(&bytes, query), None);
        assert_eq!(
            DnsQuestionWriter::new(&mut [0u8; 512]).write_a_query(1, &name),
            None
        );
    }

    #[test]
    fn malformed_address_records_are_skipped_without_failing_the_response() {
        // A CNAME and an AAAA record whose RDATA length lies about the
        // family must not stop the AAAA record behind them from parsing.
        let bytes = response_for(
            "example.com",
            TYPE_AAAA,
            CLASS_IN,
            &[
                (Owner::Question, TYPE_CNAME, alloc::vec![0xc0, 0x0c]),
                (Owner::Question, TYPE_AAAA, alloc::vec![1, 2, 3]),
                (
                    Owner::Question,
                    TYPE_AAAA,
                    alloc::vec![0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
                ),
            ],
        );
        let message = parse(&bytes, EXAMPLE_AAAA).expect("response should parse");

        assert_eq!(
            message.addresses.as_slice(),
            &[IpAddress::Ipv6(Ipv6Address::new([
                0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3
            ]))]
        );
    }

    #[test]
    fn responses_beyond_the_record_cap_truncate_instead_of_failing() {
        let addresses: alloc::vec::Vec<(u16, &[u8])> = (0..DNS_MAX_ADDRESS_RECORDS + 4)
            .map(|_| (TYPE_A, &[10, 0, 0, 1][..]))
            .collect();
        let bytes = response_with(&addresses);
        let message = parse(&bytes, EXAMPLE_A).expect("oversized response should still parse");

        assert_eq!(message.addresses.len(), DNS_MAX_ADDRESS_RECORDS);
    }

    fn https_rdata(priority: u16, target: &str, params: &[(u16, &[u8])]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        out.extend_from_slice(&priority.to_be_bytes());
        if target == "." {
            out.push(0);
        } else {
            push_name(&mut out, target);
        }
        for (key, value) in params {
            out.extend_from_slice(&key.to_be_bytes());
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    fn alpn_param(ids: &[&str]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        for id in ids {
            out.push(id.len() as u8);
            out.extend_from_slice(id.as_bytes());
        }
        out
    }

    fn https_response_for(
        qname: &str,
        flags: u16,
        answers: &[(Owner<'_>, u16, u32, alloc::vec::Vec<u8>)],
    ) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec::Vec::new();
        bytes.extend_from_slice(&0x4242u16.to_be_bytes());
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        push_name(&mut bytes, qname);
        bytes.extend_from_slice(&TYPE_HTTPS.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        for (owner, record_type, ttl, data) in answers {
            match owner {
                Owner::Question => bytes.extend_from_slice(&[0xc0, 0x0c]),
                Owner::Name(name) => push_name(&mut bytes, name),
            }
            bytes.extend_from_slice(&record_type.to_be_bytes());
            bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
            bytes.extend_from_slice(&ttl.to_be_bytes());
            bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
            bytes.extend_from_slice(data);
        }
        bytes
    }

    fn parse_https<'a>(bytes: &'a [u8], host: &str, port: u16) -> Option<DnsHttpsOutcome<'a>> {
        let qname = DnsWireName::https_qname(host, port)?;
        let origin = DnsWireName::from_host(host)?;
        DnsResponse::parse(bytes).and_then(|response| response.https_outcome(&qname, &origin))
    }

    #[test]
    fn https_query_encodes_bare_host_on_443_and_service_prefix_on_non_default_ports() {
        let mut default_buf = [0u8; 128];
        let default_len = DnsQuestionWriter::new(&mut default_buf)
            .write_https_query(9, "example.com", 443)
            .expect("443 HTTPS query should encode");
        assert_eq!(
            u16::from_be_bytes([default_buf[default_len - 4], default_buf[default_len - 3]]),
            TYPE_HTTPS
        );
        assert_eq!(
            &default_buf[QUESTION_OFFSET..default_len - 4],
            wire_name("example.com").as_slice()
        );

        let mut alt_buf = [0u8; 128];
        let alt_len = DnsQuestionWriter::new(&mut alt_buf)
            .write_https_query(9, "example.com", 8443)
            .expect("non-default HTTPS query should encode");
        assert_eq!(
            &alt_buf[QUESTION_OFFSET..alt_len - 4],
            wire_name("_8443._https.example.com").as_slice()
        );
    }

    #[test]
    fn https_service_mode_decodes_alpn_port_and_minimum_ttl() {
        let alpn = alpn_param(&["h2", "h3"]);
        let port = 8443u16.to_be_bytes();
        let bytes = https_response_for(
            "_8443._https.example.com",
            0x8180,
            &[(
                Owner::Question,
                TYPE_HTTPS,
                300,
                https_rdata(1, ".", &[(1, &alpn), (3, &port)]),
            )],
        );

        let Some(DnsHttpsOutcome::Service(record)) = parse_https(&bytes, "example.com", 8443)
        else {
            panic!("expected ServiceMode HTTPS record");
        };
        assert_eq!(record.alpn.as_slice(), &["h2", "h3"]);
        assert_eq!(record.port, Some(8443));
        assert_eq!(record.ttl_seconds, 300);
    }

    #[test]
    fn https_multiple_priorities_pick_lowest_nonzero_priority_and_shortest_ttl() {
        let h2_only = alpn_param(&["h2"]);
        let h3_alpn = alpn_param(&["h3", "h2"]);
        let port_9443 = 9443u16.to_be_bytes();
        let bytes = https_response_for(
            "example.com",
            0x8180,
            &[
                (
                    Owner::Question,
                    TYPE_HTTPS,
                    400,
                    https_rdata(10, ".", &[(1, &h2_only)]),
                ),
                (
                    Owner::Question,
                    TYPE_HTTPS,
                    120,
                    https_rdata(2, "example.com", &[(1, &h3_alpn), (3, &port_9443)]),
                ),
                (
                    Owner::Question,
                    TYPE_HTTPS,
                    90,
                    https_rdata(5, ".", &[(1, &h2_only)]),
                ),
            ],
        );

        let Some(DnsHttpsOutcome::Service(record)) = parse_https(&bytes, "example.com", 443) else {
            panic!("expected priority 2 ServiceMode record");
        };
        assert_eq!(record.alpn.as_slice(), &["h3", "h2"]);
        assert_eq!(record.port, Some(9443));
        assert_eq!(record.ttl_seconds, 90);
    }

    #[test]
    fn https_follows_cname_and_alias_mode_chains_within_limit() {
        let h3 = alpn_param(&["h3"]);
        let bytes = https_response_for(
            "example.com",
            0x8180,
            &[
                (
                    Owner::Name("svc.edge.example"),
                    TYPE_HTTPS,
                    300,
                    https_rdata(1, ".", &[(1, &h3)]),
                ),
                (
                    Owner::Name("alias.edge.example"),
                    TYPE_HTTPS,
                    45,
                    https_rdata(0, "svc.edge.example", &[]),
                ),
                (
                    Owner::Question,
                    TYPE_CNAME,
                    180,
                    wire_name("alias.edge.example"),
                ),
            ],
        );

        let Some(DnsHttpsOutcome::Service(record)) = parse_https(&bytes, "example.com", 443) else {
            panic!("expected CNAME + AliasMode chain to resolve");
        };
        assert_eq!(record.alpn.as_slice(), &["h3"]);
        assert_eq!(record.ttl_seconds, 45);
    }

    #[test]
    fn https_external_alias_mode_reports_target_for_follow_up_query() {
        let bytes = https_response_for(
            "alias.test",
            0x8180,
            &[(
                Owner::Question,
                TYPE_HTTPS,
                150,
                https_rdata(0, "real.test", &[]),
            )],
        );

        let Some(DnsHttpsOutcome::Alias {
            target,
            ttl_seconds,
            hops,
        }) = parse_https(&bytes, "alias.test", 443)
        else {
            panic!("expected Alias outcome when target is not in packet");
        };
        assert_eq!(target, DnsWireName::from_host("real.test").unwrap());
        assert_eq!(ttl_seconds, 150);
        assert_eq!(hops, 1);
    }

    #[test]
    fn https_root_alias_mode_voids_service_records_and_returns_no_record() {
        let h3 = alpn_param(&["h3"]);
        let bytes = https_response_for(
            "example.com",
            0x8180,
            &[
                (
                    Owner::Question,
                    TYPE_HTTPS,
                    300,
                    https_rdata(1, ".", &[(1, &h3)]),
                ),
                (Owner::Question, TYPE_HTTPS, 300, https_rdata(0, ".", &[])),
            ],
        );

        assert_eq!(
            parse_https(&bytes, "example.com", 443),
            Some(DnsHttpsOutcome::NoRecord)
        );
    }

    #[test]
    fn https_chain_past_limit_or_looping_resolves_to_no_record() {
        let h3 = alpn_param(&["h3"]);
        let links: alloc::vec::Vec<alloc::string::String> = (1..=DNS_MAX_CNAME_CHAIN + 1)
            .map(|step| alloc::format!("hop{step}.example"))
            .collect();
        let mut answers = alloc::vec![(Owner::Question, TYPE_CNAME, 60, wire_name(&links[0]),)];
        for pair in links.windows(2) {
            answers.push((
                Owner::Name(&pair[0]),
                TYPE_HTTPS,
                60,
                https_rdata(0, &pair[1], &[]),
            ));
        }
        answers.push((
            Owner::Name(&links[DNS_MAX_CNAME_CHAIN]),
            TYPE_HTTPS,
            60,
            https_rdata(1, ".", &[(1, &h3)]),
        ));
        let too_deep = https_response_for("example.com", 0x8180, &answers);
        assert_eq!(
            parse_https(&too_deep, "example.com", 443),
            Some(DnsHttpsOutcome::NoRecord)
        );

        let cycle = https_response_for(
            "example.com",
            0x8180,
            &[
                (
                    Owner::Question,
                    TYPE_HTTPS,
                    60,
                    https_rdata(0, "loop.example", &[]),
                ),
                (
                    Owner::Name("loop.example"),
                    TYPE_HTTPS,
                    60,
                    https_rdata(0, "example.com", &[]),
                ),
            ],
        );
        assert_eq!(
            parse_https(&cycle, "example.com", 443),
            Some(DnsHttpsOutcome::NoRecord)
        );
    }

    #[test]
    fn https_nxdomain_and_nodata_return_no_record_while_servfail_is_server_failure() {
        let nodata = https_response_for("example.com", 0x8180, &[]);
        assert_eq!(
            parse_https(&nodata, "example.com", 443),
            Some(DnsHttpsOutcome::NoRecord)
        );

        let nxdomain = https_response_for("example.com", 0x8183, &[]);
        assert_eq!(
            parse_https(&nxdomain, "example.com", 443),
            Some(DnsHttpsOutcome::NoRecord)
        );

        let servfail = https_response_for("example.com", 0x8182, &[]);
        assert_eq!(
            parse_https(&servfail, "example.com", 443),
            Some(DnsHttpsOutcome::ServerFailure(2))
        );

        // Wrong question echo on NXDOMAIN/SERVFAIL is ignored (`None`), never
        // accepted as an answer for `example.com`.
        let forged_nxdomain = https_response_for("other.example", 0x8183, &[]);
        assert_eq!(parse_https(&forged_nxdomain, "example.com", 443), None);
    }

    #[test]
    fn https_rejects_duplicate_out_of_order_truncated_and_incompatible_svc_params() {
        let h3 = alpn_param(&["h3"]);
        let port = 8443u16.to_be_bytes();

        // Out-of-order keys (3 before 1).
        let out_of_order = https_response_for(
            "example.com",
            0x8180,
            &[(
                Owner::Question,
                TYPE_HTTPS,
                60,
                https_rdata(1, ".", &[(3, &port), (1, &h3)]),
            )],
        );
        assert_eq!(
            parse_https(&out_of_order, "example.com", 443),
            Some(DnsHttpsOutcome::NoRecord)
        );

        // Duplicate keys (1 twice).
        let duplicate = https_response_for(
            "example.com",
            0x8180,
            &[(
                Owner::Question,
                TYPE_HTTPS,
                60,
                https_rdata(1, ".", &[(1, &h3), (1, &h3)]),
            )],
        );
        assert_eq!(
            parse_https(&duplicate, "example.com", 443),
            Some(DnsHttpsOutcome::NoRecord)
        );

        // Truncated RDATA (claims 10-byte SvcParamValue with only 2 bytes left).
        let truncated_rdata = https_response_for(
            "example.com",
            0x8180,
            &[(
                Owner::Question,
                TYPE_HTTPS,
                60,
                alloc::vec![0, 1, 0, 0, 1, 0, 10, 2, b'h'],
            )],
        );
        assert_eq!(
            parse_https(&truncated_rdata, "example.com", 443),
            Some(DnsHttpsOutcome::NoRecord)
        );

        // Compression pointer in TargetName (forbidden by RFC 9460 §2.2 / RFC 3597).
        let compressed_target = https_response_for(
            "example.com",
            0x8180,
            &[(
                Owner::Question,
                TYPE_HTTPS,
                60,
                alloc::vec![0, 1, 0xc0, 0x0c, 0, 1, 0, 3, 2, b'h', b'3'],
            )],
        );
        assert_eq!(
            parse_https(&compressed_target, "example.com", 443),
            Some(DnsHttpsOutcome::NoRecord)
        );

        // Mandatory unknown key (key 5 = ech) on priority 1 is skipped so
        // compatible priority 2 wins; mandatory key 1 + 3 present succeeds.
        let mandatory_ech = 5u16.to_be_bytes();
        let mandatory_alpn_port = [0u8, 1, 0, 3];
        let fallback_ok = https_response_for(
            "example.com",
            0x8180,
            &[
                (
                    Owner::Question,
                    TYPE_HTTPS,
                    60,
                    https_rdata(1, ".", &[(0, &mandatory_ech), (1, &h3), (5, &[1, 2, 3, 4])]),
                ),
                (
                    Owner::Question,
                    TYPE_HTTPS,
                    60,
                    https_rdata(2, ".", &[(0, &mandatory_alpn_port), (1, &h3), (3, &port)]),
                ),
            ],
        );
        let Some(DnsHttpsOutcome::Service(record)) = parse_https(&fallback_ok, "example.com", 443)
        else {
            panic!("compatible priority 2 record should win when priority 1 has mandatory ech");
        };
        assert_eq!(record.alpn.as_slice(), &["h3"]);
        assert_eq!(record.port, Some(8443));

        // Missing mandatory key (mandatory lists port=3, RR omits key 3).
        let missing_mandatory = https_response_for(
            "example.com",
            0x8180,
            &[(
                Owner::Question,
                TYPE_HTTPS,
                60,
                https_rdata(1, ".", &[(0, &3u16.to_be_bytes()), (1, &h3)]),
            )],
        );
        assert_eq!(
            parse_https(&missing_mandatory, "example.com", 443),
            Some(DnsHttpsOutcome::NoRecord)
        );
    }
}
