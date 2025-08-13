#![no_std]
#![forbid(unsafe_code)]
//! Generic implementation of the CCSDS 133.0-B-2 Space Packet Protocol (SPP). That is, this crate
//! concerns itself only with parsing and construction of CCSDS Space Packets, as that is
//! independent of the precise implementation. Endpoint functionality, i.e., actually consuming and
//! responding to the packet contents is implementation specific, and hence out of scope.
//!
//! Readers of the code are advised to start with the `PacketAssembly`, `PacketTransfer`,
//! `PacketReception` and `PacketExtraction` traits. These describe the interfaces that application
//! processes supporting the Space Packet Protocol are expected to expose. The underlying parsing
//! and semantic checking functionality is found in the actual `SpacePacket` implementation.

use zerocopy::byteorder::network_endian;
use zerocopy::{ByteEq, CastError, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// The `PacketAssembly` trait describes the "Packet Assembly" function from the CCSDS 133.0-B-2
/// Space Packet Protocol recommended standard. This function concerns the ability of some protocol
/// entity to build Space Packets from octet strings (packet data fields). It is the sending
/// counterpart of the `PacketExtraction` trait.
///
/// We deviate slightly from the strict "Packet Assembly" function definition in permitting
/// population of the octet string only after assembly of a packet with given packet data field
/// length. This is useful, because it means that no copy is needed to prepend the Space Packet
/// header to the data field, which saves a `memcpy`.
pub trait PacketAssembly: PacketTransfer {
    /// An error may be returned if the requested Space Packet could not be assembled. An
    /// appropriate default value would be `SpacePacketAssemblyError`. However, it is also possible
    /// that the underlying implementation raises an application-specific error, as could be the
    /// case when the `PacketAssembly` function has run out of memory.
    type Error;

    /// Generates Space Packets from octet strings. See CCSDS 133.0-B-2 Section 4.2.2 "Packet
    /// Assembly Function". A secondary header indicator must be passed as well as the requested
    /// data field size, but all other packet header contents must be derived from context. In
    /// particular, the Packet Assembly function shall itself keep track of the source sequence
    /// count of packets.
    ///
    /// It is not possible to "accidentally" send the Space Packet while it is still being
    /// constructed, because a mutable reference is returned. How this sending is done is
    /// implementation-defined (using the `PacketTransfer::transfer()` trait method), but at the
    /// very least it cannot (in safe Rust) be done without dropping the mutable reference first.
    /// After all, the memory that the sending function must read from (`self`) is still being
    /// aliased with a mutable reference.
    fn assemble(
        &mut self,
        secondary_header: SecondaryHeaderFlag,
        packet_data_length: usize,
    ) -> Result<&mut SpacePacket, Self::Error>;
}

/// The `PacketTransfer` trait describes the "Packet Transfer" function from the CCSDS 133.0-B-2
/// Space Packet Protocol recommended standard. It concerns the ability of some protocol entity to
/// transfer packets towards the appropriate managed data path. It is the sending counterpart of
/// the `PacketReception` trait.
pub trait PacketTransfer {
    /// Inspects an incoming or newly-created Space Packet (its APID, in particular) to determine
    /// the target packet service entity at the receiving end. Routes this packet towards the
    /// appropriate managed data path using a service of the underlying OSI reference model layers.
    fn transfer(&mut self, packet: &SpacePacket);
}

/// The `PacketReception` trait describes the "Packet Reception" function from the CCSDS 133.0-B-2
/// Space Packet Protocol recommended standard. It concerns the ability of some protocol entity to
/// receive and demultiplex Space Packets from the underlying subnetwork. It is the receiving
/// counterpart of the `PacketTransfer` trait.
pub trait PacketReception {
    /// Inspects an incoming Space Packet from the underlying subnetwork. Shall demultiplex, if
    /// applicable, the received packets based on the contained APIDs.
    fn receive(&mut self) -> Result<&SpacePacket, InvalidSpacePacket>;
}

/// The `PacketExtraction` trait describes the "Packet Extraction" function from the CCSDS
/// 133.0-B-2 Space Packet Protocol recommended standard. It concerns the ability of some protocol
/// entity to extract service data units (SDUs) from Space Packets. Effectivelly, it is little more
/// than unwrapping the received packet into its data field.
pub trait PacketExtraction: PacketReception {
    /// In addition to the octet string contained in a packet, the Packet Extraction function shall
    /// check the continuity of the Packet Sequence Count to determine if one or more packets have
    /// been lost during transmission. If this is the case, an associated `DataLossIndicator` value
    /// may be returned to indicate this. However, this type may also be the unit type, if such
    /// functionality is not supported.
    type DataLossIndicator;

    /// The Packet Extraction function shall extract Service Data Units (SDUs), i.e., packet data
    /// fields, from received Space Packets. Shall returned the wrapped packet data field, a flag
    /// indicating whether a secondary header is present (at the start of the data field) and an
    /// optional Data Loss Indicator.
    #[allow(clippy::type_complexity)]
    fn extract(
        &mut self,
    ) -> Result<(&[u8], SecondaryHeaderFlag, Self::DataLossIndicator), InvalidSpacePacket>;
}

/// Space packets are implemented as dynamically-sized structs that contain the primary header as
/// their first field, followed by the packet data as pure byte array. In this manner,
/// deserialization can be reduced to a simple byte cast followed by interpretation of the primary
/// header - without any data copies needed. This is useful for high-throughput applications, and
/// ensures that no allocation or significant additional memory is needed to consume Space Packets.
///
/// This does also mean that Space Packets may only be handled by reference. In the context of this
/// crate that helps enforce that no spurious copies can be made of the user data (which may be
/// rather large and would incur additional allocations), albeit at the cost of some convenience.
///
/// Any means of constructing a SpacePacket in this crate shall perform a consistency check on any
/// received bytes. Hence, any SpacePacket object may be assumed to be a valid Space Packet.
#[repr(C, packed)]
#[derive(ByteEq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct SpacePacket {
    packet_identification: network_endian::U16,
    packet_sequence_control: network_endian::U16,
    data_length: network_endian::U16,
    data_field: [u8],
}

impl SpacePacket {
    /// Attempts to parse a Space Packet from a given byte slice. If this fails, a reason is
    /// given for this failure. Shall never panic: rather, an error enum is returned explaining why
    /// the given octet string is not a valid Space Packet.
    ///
    /// This deserialization is fully zero-copy. The `&SpacePacket` returned on success directly
    /// references the input slice `bytes`, but is merely validated to be a valid Space Packet.
    pub fn extract(bytes: &[u8]) -> Result<&SpacePacket, InvalidSpacePacket> {
        // First, we simply cast the packet into a header and check that the byte buffer permits
        // this: i.e., if it is large enough to contain a header.
        let primary_header = match SpacePacket::ref_from_bytes(bytes) {
            Ok(primary_header) => primary_header,
            Err(CastError::Size(_)) => {
                return Err(InvalidSpacePacket::SliceTooSmallForSpacePacketHeader {
                    length: bytes.len(),
                });
            }
            Err(CastError::Alignment(_)) => unreachable!(),
        };

        // Then, we verify that the resulting packet contents semantically form a valid space
        // packet.
        primary_header.validate()?;

        // Finally, we truncate the passed byte slice to exactly accommodate the specified space
        // packet and construct a Space Packet that consists of only this memory region.
        let packet_size = primary_header.packet_data_length() + Self::primary_header_size();
        let packet_bytes = &bytes[..packet_size];
        let packet = match SpacePacket::ref_from_bytes(packet_bytes) {
            Ok(primary_header) => primary_header,
            Err(_) => unreachable!(),
        };

        Ok(packet)
    }

    /// Constructs a Space Packet in-place on a given buffer. May return a
    /// `SpacePacketConstructionError` if this is not possible for whatever reason. Note that the
    /// data field is only "allocated" on the buffer, but never further populated. That may be done
    /// after the SpacePacket is otherwise fully constructed.
    pub fn assemble(
        buffer: &mut [u8],
        packet_type: PacketType,
        secondary_header_flag: SecondaryHeaderFlag,
        apid: Apid,
        sequence_flag: SequenceFlag,
        sequence_count: PacketSequenceCount,
        packet_data_length: u16,
    ) -> Result<&mut SpacePacket, SpacePacketAssemblyError> {
        // As per the CCSDS Space Packet Protocol standard, we must reject requests for data field
        // lengths of zero.
        if packet_data_length == 0 {
            return Err(SpacePacketAssemblyError::EmptyDataFieldRequested);
        }

        // Verify that the packet length as requested may actually fit on the supplied buffer.
        let packet_length = SpacePacket::primary_header_size() + packet_data_length as usize;
        let buffer_length = buffer.len();
        if packet_length > buffer_length {
            return Err(SpacePacketAssemblyError::BufferTooSmall {
                buffer_length,
                packet_length,
            });
        }

        // Afterwards, we truncate the buffer to use only the bytes that actually belong to the
        // packet. With the length check done, the `SpacePacket::mut_from_bytes()` call is known
        // to be infallible, so we simply unwrap.
        let packet_bytes = &mut buffer[..packet_length];
        let packet = SpacePacket::mut_from_bytes(packet_bytes).unwrap();

        // Initialize header bytes to valid values.
        packet.set_apid(apid);
        packet.initialize_packet_version();
        packet.set_packet_type(packet_type);
        packet.set_secondary_header_flag(secondary_header_flag);
        packet.set_sequence_flag(sequence_flag);
        packet.set_packet_sequence_count(sequence_count);
        packet.set_packet_data_length(packet_data_length)?;

        Ok(packet)
    }

    /// Validates that the Space Packet is valid, in that its fields are coherent. In particular,
    /// it is verified that the version number is that of a supported Space Packet, and that the
    /// packet size as stored in the header is not larger than the packet size as permitted by the
    /// actual memory span of which the packet consists.
    ///
    /// Note that this concerns semantic validity. The implementation shall not depend on this for
    /// memory safety.
    fn validate(&self) -> Result<(), InvalidSpacePacket> {
        // Then, we verify that the packet version found in the packet header is a version that is
        // supported by this library.
        let version = self.packet_version();
        if !version.is_supported() {
            return Err(InvalidSpacePacket::UnsupportedPacketVersion { version });
        }

        // The packet header contains an indication of the actual amount of bytes stored in the packet.
        // If this is larger than the size of the actual memory contents, only a partial packet was
        // received.
        let packet_size = self.packet_data_length() + Self::primary_header_size();
        let buffer_size = self.packet_length();
        if packet_size > buffer_size {
            return Err(InvalidSpacePacket::PartialPacket {
                packet_size,
                buffer_size,
            });
        }

        Ok(())
    }

    /// Returns the size of a Space Packet primary header, in bytes. In the version that is
    /// presently implemented, that is always 6 bytes.
    pub const fn primary_header_size() -> usize {
        6
    }

    /// Since the Space Packet protocol may technically support alternative packet structures in
    /// future versions, the 3-bit packet version field may not actually contain a "correct" value.
    pub fn packet_version(&self) -> PacketVersionNumber {
        use core::ops::Shr;
        PacketVersionNumber(self.packet_identification.as_bytes()[0].shr(5))
    }

    /// Initializes the packet version to the proper value. Must be a fixed value, so this function
    /// takes no arguments.
    pub fn initialize_packet_version(&mut self) {
        self.packet_identification.as_mut_bytes()[0] &= 0b0001_1111;
        self.packet_identification.as_mut_bytes()[0] |=
            PacketVersionNumber::version1_ccsds_packet().0 << 5;
    }

    /// The packet type denotes whether a packet is a telecommand (request) or telemetry (report)
    /// packet. Note that the exact definition of telecommand and telemetry may differ per system,
    /// and indeed the "correct" value here may differ per project.
    pub fn packet_type(&self) -> PacketType {
        match (self.packet_identification.as_bytes()[0] & 0x10) == 0x10 {
            true => PacketType::Telecommand,
            false => PacketType::Telemetry,
        }
    }

    /// Sets the packet type to the given value.
    pub fn set_packet_type(&mut self, packet_type: PacketType) {
        self.packet_identification.as_mut_bytes()[0] &= 0b1110_1111;
        self.packet_identification.as_mut_bytes()[0] |= (packet_type as u8) << 4;
    }

    /// Denotes whether the packet contains a secondary header. If no user field is present, the
    /// secondary header is mandatory (presumably, to ensure that some data is always transferred,
    /// considering the Space Packet header itself contains no meaningful data).
    pub fn secondary_header_flag(&self) -> SecondaryHeaderFlag {
        match (self.packet_identification.as_bytes()[0] & 0x08) == 0x08 {
            true => SecondaryHeaderFlag::Present,
            false => SecondaryHeaderFlag::Absent,
        }
    }

    /// Updates the value of the secondary header flag with the provided value.
    pub fn set_secondary_header_flag(&mut self, secondary_header_flag: SecondaryHeaderFlag) {
        self.packet_identification.as_mut_bytes()[0] &= 0b1111_0111;
        self.packet_identification.as_mut_bytes()[0] |= (secondary_header_flag as u8) << 3;
    }

    /// Returns the application process ID stored in the packet. The actual meaning of this APID
    /// field may differ per implementation: technically, it only represents "some" data path.
    /// In practice, it will often be a identifier for a data channel, the packet source, or the
    /// packet destination.
    pub fn apid(&self) -> Apid {
        Apid(self.packet_identification.get() & 0b0000_0111_1111_1111)
    }

    /// Sets the APID used to route the packet to the given value.
    pub fn set_apid(&mut self, apid: Apid) {
        let apid = apid.0.to_be_bytes();
        self.packet_identification.as_mut_bytes()[0] &= 0b1111_1000;
        self.packet_identification.as_mut_bytes()[0] |= apid[0] & 0b0000_0111;
        self.packet_identification.as_mut_bytes()[1] = apid[1];
    }

    /// Sequence flags may be used to indicate that the data contained in a packet is only part of
    /// a larger set of application data.
    pub fn sequence_flag(&self) -> SequenceFlag {
        use core::ops::Shr;
        match self.packet_sequence_control.as_bytes()[0].shr(6i32) {
            0b00 => SequenceFlag::Continuation,
            0b01 => SequenceFlag::First,
            0b10 => SequenceFlag::Last,
            0b11 => SequenceFlag::Unsegmented,
            _ => unreachable!("Internal error: Reached unreachable code segment"),
        }
    }

    /// Sets the sequence flag to the provided value.
    pub fn set_sequence_flag(&mut self, sequence_flag: SequenceFlag) {
        self.packet_sequence_control.as_mut_bytes()[0] &= 0b0011_1111;
        self.packet_sequence_control.as_mut_bytes()[0] |= (sequence_flag as u8) << 6;
    }

    /// The packet sequence count is unique per APID and denotes the sequential binary count of
    /// each Space Packet (generated per APID). For telecommands (i.e., with packet type 1) this
    /// may also be a "packet name" that identifies the telecommand packet within its
    /// communications session.
    pub fn packet_sequence_count(&self) -> PacketSequenceCount {
        PacketSequenceCount(self.packet_sequence_control.get() & 0b0011_1111_1111_1111)
    }

    /// Sets the packet sequence count to the provided value. This value must be provided by an
    /// external counter and is not provided at a Space Packet type level because it might differ
    /// between packet streams.
    pub fn set_packet_sequence_count(&mut self, sequence_count: PacketSequenceCount) {
        self.packet_sequence_control.as_mut_bytes()[0] &= 0b1100_0000;
        self.packet_sequence_control.as_mut_bytes()[0] |=
            sequence_count.0.to_be_bytes()[0] & 0b0011_1111;
        self.packet_sequence_control.as_mut_bytes()[1] = sequence_count.0.to_be_bytes()[1];
    }

    /// The packet data length field represents the length of the associated packet data field.
    /// However, it is not stored directly: rather, the "length count" is stored, which is the
    /// packet data length minus one.
    pub fn packet_data_length(&self) -> usize {
        self.data_length.get() as usize + 1
    }

    /// Sets the packet data length field to the provided value. Note that the given value is not
    /// stored directly, but rather decremented by one first. Accordingly, and as per the CCSDS
    /// Space Packet Protocol standard, packet data lengths of 0 are not allowed.
    pub fn set_packet_data_length(
        &mut self,
        packet_data_length: u16,
    ) -> Result<(), InvalidPacketDataLength> {
        if packet_data_length == 0 {
            return Err(InvalidPacketDataLength::EmptyDataField);
        }

        let buffer_length = self.data_field.len();
        if packet_data_length as usize > buffer_length {
            return Err(InvalidPacketDataLength::LargerThanPacketDataBuffer {
                packet_data_length,
                buffer_length,
            });
        }

        let stored_data_field_length = packet_data_length - 1;
        self.data_length.set(stored_data_field_length);
        Ok(())
    }

    /// Returns the total length of the packet in bytes. Note the distinction from the packet data
    /// length, which refers only to the length of the data field of the packet.
    pub fn packet_length(&self) -> usize {
        self.as_bytes().len()
    }

    /// Returns a reference to the packet data field contained in this Space Packet.
    pub fn packet_data_field(&self) -> &[u8] {
        &self.data_field
    }

    /// Returns a mutable reference to the packet data field contained in this Space Packet.
    pub fn packet_data_field_mut(&mut self) -> &mut [u8] {
        &mut self.data_field
    }
}

/// Because `SpacePacket` is `repr(packed)` and `SpacePacket::data_field` is unsized, the default
/// `core::fmt::Debug` implementation cannot be derived.
impl core::fmt::Debug for SpacePacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SpacePacket {{ version number: {:?}, packet type: {:?}, secondary header flag: {:?}, APID: {:?}, sequence flags: {:?}, sequence count: {:?}, packet data length: {:?}, packet data: {:?} }}",
            self.packet_version(),
            self.packet_type(),
            self.secondary_header_flag(),
            self.apid(),
            self.sequence_flag(),
            self.packet_sequence_count(),
            self.packet_data_length(),
            self.packet_data_field(),
        )
    }
}

/// Representation of the set of errors that may be encountered while deserializing a Space Packet.
/// Marked as non-exhaustive to permit extension with additional semantic errors in the future
/// without breaking API.
#[non_exhaustive]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum InvalidSpacePacket {
    /// Returned when a byte slice is too small to contain any Space Packet (i.e., is smaller than
    /// a header with a single-byte user data field).
    SliceTooSmallForSpacePacketHeader { length: usize },
    /// Returned when a slice does not have a known and supported packet version. For convenience,
    /// the packet version that is stored at the "conventional" (CCSDS packet version 0) is also
    /// returned, though it does not need to be meaningful in other packet versions.
    UnsupportedPacketVersion { version: PacketVersionNumber },
    /// Returned when the decoded packet is not fully contained in the passed buffer.
    PartialPacket {
        packet_size: usize,
        buffer_size: usize,
    },
}

/// Representation of the set of errors that may be encountered while constructing a Space Packet.
/// Marked as non-exhaustive to permit extension with additional semantic errors in the future
/// without breaking API.
#[non_exhaustive]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum SpacePacketAssemblyError {
    /// Returned when the underlying buffer does not have sufficient bytes to contain a given space
    /// packet.
    BufferTooSmall {
        buffer_length: usize,
        packet_length: usize,
    },
    /// As per the CCSDS standard, Space Packets shall have at least one byte in their data field.
    /// Hence, requests for an empty data field must be rejected.
    EmptyDataFieldRequested,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum InvalidPacketDataLength {
    EmptyDataField,
    LargerThanPacketDataBuffer {
        packet_data_length: u16,
        buffer_length: usize,
    },
}

impl From<InvalidPacketDataLength> for SpacePacketAssemblyError {
    fn from(value: InvalidPacketDataLength) -> Self {
        match value {
            InvalidPacketDataLength::EmptyDataField => {
                SpacePacketAssemblyError::EmptyDataFieldRequested
            }
            InvalidPacketDataLength::LargerThanPacketDataBuffer {
                packet_data_length,
                buffer_length,
            } => SpacePacketAssemblyError::BufferTooSmall {
                buffer_length: buffer_length + SpacePacket::primary_header_size(),
                packet_length: packet_data_length as usize + SpacePacket::primary_header_size(),
            },
        }
    }
}

/// The packet version number represents the version of the Space Packet protocol that is used. In
/// the version presently implemented, this is defined to be zeroes.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct PacketVersionNumber(u8);

impl PacketVersionNumber {
    /// The Space Packet protocol version presently implemented in this crate is based on issue 2
    /// of the CCSDS SPP blue book, which encompasses only the Version 1 CCSDS Packet, indicated by
    /// a version number of 0. Other packet structures may be added in the future.
    pub fn is_supported(&self) -> bool {
        matches!(self.0, 0b0000_0000u8)
    }

    /// Returns the packet version number corresponding with the Version 1 CCSDS Packet.
    pub fn version1_ccsds_packet() -> Self {
        Self(0)
    }
}

/// The packet type denotes whether a packet is a telecommand (request) or telemetry (report)
/// packet. Note that the exact definition of telecommand and telemetry may differ per system,
/// and indeed the "correct" value here may differ per project.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum PacketType {
    Telemetry = 0,
    Telecommand = 1,
}

/// Denotes whether the packet contains a secondary header. If no user field is present, the
/// secondary header is mandatory (presumably, to ensure that some data is always transferred,
/// considering the Space Packet header itself contains no meaningful data).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum SecondaryHeaderFlag {
    Absent = 0,
    Present = 1,
}

/// Returns the application process ID stored in the packet. The actual meaning of this APID
/// field may differ per implementation: technically, it only represents "some" data path.
/// In practice, it will often be a identifier for: a data channel, the packet source, or the
/// packet destination.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Apid(u16);

impl Apid {
    const MAX: u16 = 0b0000_0111_1111_1111u16;

    pub fn new(id: u16) -> Self {
        assert!(
            id <= Self::MAX,
            "APIDs may not exceed 2047 (due to maximum of 13 bits in representation)"
        );
        Self(id)
    }

    /// Helper functions used during formal verification to create an APID that is actually within
    /// the stated bounds, since we cannot use the type system to express this range.
    #[cfg(kani)]
    fn any_apid() -> Self {
        match kani::any() {
            any @ 0..=Self::MAX => Self(any),
            _ => Self(42),
        }
    }

    /// A special APID value (0x7ff) is reserved for idle Space Packets, i.e., packets that do not
    /// carry any actual data.
    pub fn is_idle(&self) -> bool {
        self.0 == 0x7ff
    }
}

/// Sequence flags may be used to indicate that the data contained in a packet is only part of
/// a larger set of application data.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum SequenceFlag {
    Continuation = 0b00,
    First = 0b01,
    Last = 0b10,
    #[default]
    Unsegmented = 0b11,
}

/// The packet sequence count is unique per APID and denotes the sequential binary count of
/// each Space Packet (generated per APID). For telecommands (i.e., with packet type 1) this
/// may also be a "packet name" that identifies the telecommand packet within its
/// communications session.
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Debug, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct PacketSequenceCount(u16);

impl PacketSequenceCount {
    const MAX: u16 = 0b0011_1111_1111_1111u16;

    /// The packet sequence count is initialized to zero by default.
    pub fn new() -> Self {
        Self(0)
    }

    /// Helper functions used during formal verification to create a packet sequence count that is
    /// actually within the stated bounds, since we cannot use the type system to express this
    /// range.
    #[cfg(kani)]
    fn any_packet_sequence_count() -> Self {
        match kani::any() {
            any @ 0..=Self::MAX => Self(any),
            _ => Self(42),
        }
    }

    /// A good default behaviour is for the packet sequence count to increment by one every time
    /// a new packet is sent. This method permits a simple wrapping increment to be performed, to
    /// make this easier.
    pub fn increment(&mut self) {
        self.0 += 1;
        if self.0 > Self::MAX {
            self.0 = 0;
        }
    }
}

/// Test harness for formal verification.
#[cfg(kani)]
mod kani_harness {
    use super::*;
    use ::kani;

    /// This test verifies that all possible primary headers may be parsed for all packets up to
    /// u16::MAX in size, without panics. Note that the packet data field is assumed to always be
    /// zero here. This is needed to restrict the search space for kani, and is a valid assumption
    /// because the parsing implementation never touches the packet data field contents.
    #[kani::proof]
    fn header_parsing() {
        let mut bytes = [0u8; u16::MAX as usize];
        bytes[0] = kani::any();
        bytes[1] = kani::any();
        bytes[2] = kani::any();
        bytes[3] = kani::any();
        bytes[4] = kani::any();
        bytes[5] = kani::any();
        bytes[6] = kani::any();

        let packet = SpacePacket::extract(&bytes);
        if let Ok(packet) = packet {
            assert!(packet.packet_length() <= bytes.len());
            assert_eq!(
                packet.packet_data_field().len(),
                packet.packet_data_length()
            );
            assert!(packet.apid().0 <= 0b0000_0111_1111_1111);
        }
    }

    /// This test verifies that all (!) possible packet construction requests can be handled
    /// without panics when working with a fixed-size buffer that does not permit all possible
    /// packet size requests. Here, we do not touch the data field, to prevent exponential blow-up
    /// of the proof pipeline. Since the packet constructor performs no actions on the packet data
    /// field beyond returning a reference to it, this makes for a strong proof about the safety of
    /// this function.
    ///
    /// The buffer size is rather arbitrarily chosen to be 1024. This covers a significant amount
    /// of valid packet sizes, but also ensures that the "error path" is covered, where the
    /// requested packet is larger than the available buffer.
    #[kani::proof]
    fn packet_construction() {
        let mut bytes = [kani::any(); 1024];
        let maximum_packet_length = bytes.len();
        let packet_type = kani::any();
        let secondary_header_flag = kani::any();
        let apid = Apid::any_apid();
        let sequence_flag = kani::any();
        let sequence_count = PacketSequenceCount::any_packet_sequence_count();
        let packet_data_length = kani::any();

        let packet = SpacePacket::assemble(
            &mut bytes,
            packet_type,
            secondary_header_flag,
            apid,
            sequence_flag,
            sequence_count,
            packet_data_length,
        );

        // First, we verify that all valid requests result in a returned packet.
        let valid_request = packet_data_length != 0
            && (packet_data_length as usize)
                <= (maximum_packet_length - SpacePacket::primary_header_size() as usize);
        if valid_request {
            assert!(packet.is_ok());
        }

        // Vice versa, any invalid requests must be rejected.
        if !valid_request {
            assert!(!packet.is_ok());
        }

        // These checks ensure that any returned packet is indeed consistent with the requested
        // packet header information.
        if let Ok(packet) = packet {
            assert!(packet.packet_length() <= maximum_packet_length);
            assert_eq!(
                packet.packet_data_field().len(),
                packet.packet_data_length()
            );

            assert_eq!(packet.packet_type(), packet_type);
            assert_eq!(packet.secondary_header_flag(), secondary_header_flag);
            assert_eq!(packet.apid(), apid);
            assert_eq!(packet.sequence_flag(), sequence_flag);
            assert_eq!(packet.packet_sequence_count(), sequence_count);
            assert_eq!(packet.packet_data_length(), packet_data_length as usize);
        }
    }
}

/// Test generated for harness `kani_harness::packet_construction` after assertion failure. Test
/// case initially failed on resizing the packet to the proper length when a larger byte buffer was
/// passed than what was covered by the packet contents.
#[test]
fn kani_failure1() {
    const BYTES: usize = 16;
    let mut bytes = [0; BYTES];
    let packet = SpacePacket::assemble(
        &mut bytes,
        PacketType::Telecommand,
        SecondaryHeaderFlag::Present,
        Apid::new(0),
        SequenceFlag::Unsegmented,
        PacketSequenceCount(65535),
        8,
    );

    if let Ok(packet) = packet {
        assert!(packet.packet_length() <= BYTES);
        assert_eq!(
            packet.packet_data_field().len(),
            packet.packet_data_length(),
            "Packet data field length does not match packet data field as stored: {packet:?}"
        );
        assert!(packet.apid().0 <= 0b0000_0111_1111_1111);
    }
}

/// Deserialization of a relatively trivial packet. Used to verify that all basic deserialization
/// logic is correct.
#[test]
fn deserialize_trivial_packet() {
    let bytes = &[
        0b0000_1000u8,
        0b0000_0000u8,
        0b1100_0000u8,
        0b0000_0000u8,
        0b0000_0000u8,
        0b0000_0000u8,
        0b0000_0000u8,
    ];
    let packet = SpacePacket::extract(bytes).unwrap();

    assert_eq!(packet.packet_length(), 7);
    assert_eq!(
        packet.packet_version(),
        PacketVersionNumber::version1_ccsds_packet()
    );
    assert_eq!(packet.packet_type(), PacketType::Telemetry);
    assert_eq!(packet.secondary_header_flag(), SecondaryHeaderFlag::Present);
    assert_eq!(packet.apid(), Apid::new(0));
    assert_eq!(packet.sequence_flag(), SequenceFlag::Unsegmented);
    assert_eq!(packet.packet_sequence_count(), PacketSequenceCount(0));
    assert_eq!(packet.packet_data_length(), 1);
    assert_eq!(packet.packet_data_field(), &bytes[6..]);
}

/// Serialization of a relatively trivial packet. Used to verify that all serialization logic is
/// correct.
#[test]
fn serialize_trivial_packet() {
    let mut bytes = [0u8; 7];
    let packet = SpacePacket::assemble(
        &mut bytes,
        PacketType::Telemetry,
        SecondaryHeaderFlag::Present,
        Apid::new(0),
        SequenceFlag::Unsegmented,
        PacketSequenceCount(0),
        1,
    )
    .unwrap();

    assert_eq!(packet.packet_length(), 7);
    assert_eq!(
        packet.packet_version(),
        PacketVersionNumber::version1_ccsds_packet()
    );
    assert_eq!(packet.packet_type(), PacketType::Telemetry);
    assert_eq!(packet.secondary_header_flag(), SecondaryHeaderFlag::Present);
    assert_eq!(packet.apid(), Apid::new(0));
    assert_eq!(packet.sequence_flag(), SequenceFlag::Unsegmented);
    assert_eq!(packet.packet_sequence_count(), PacketSequenceCount(0));
    assert_eq!(packet.packet_data_length(), 1);
    assert_eq!(
        packet.packet_data_field(),
        &[
            0b0000_1000u8,
            0b0000_0000u8,
            0b1100_0000u8,
            0b0000_0000u8,
            0b0000_0000u8,
            0b0000_0000u8,
            0b0000_0000u8,
        ][6..]
    );
}

/// Roundtrip serialization and subsequent deserialization of Space Packets shall result in exactly
/// identical byte slices for any valid (!) input. We test this by generating 10,000 random space
/// packets and seeing whether they remain identical through this transformation.
///
/// Since this test only considers valid inputs, other unit tests are needed to cover off-nominal
/// cases, such as when the buffer is too small or when the requested data field size is 0.
#[test]
fn roundtrip() {
    use rand::{RngCore, SeedableRng};
    // Note that we always use the same seed for reproducibility.
    let mut rng = rand::rngs::SmallRng::seed_from_u64(42);
    let mut buffer = [0u8; 16000];
    for _ in 0..10_000 {
        let packet_type = match rng.next_u32() & 1 {
            0 => PacketType::Telemetry,
            1 => PacketType::Telecommand,
            _ => unreachable!(),
        };
        let secondary_header_flag = match rng.next_u32() & 1 {
            0 => SecondaryHeaderFlag::Absent,
            1 => SecondaryHeaderFlag::Present,
            _ => unreachable!(),
        };
        let apid = Apid::new((rng.next_u32() & Apid::MAX as u32) as u16);
        let sequence_flag = match rng.next_u32() & 3 {
            0b00 => SequenceFlag::Continuation,
            0b01 => SequenceFlag::First,
            0b10 => SequenceFlag::Last,
            0b11 => SequenceFlag::Unsegmented,
            _ => unreachable!(),
        };
        let sequence_count =
            PacketSequenceCount((rng.next_u32() & PacketSequenceCount::MAX as u32) as u16);

        let packet_data_length = (rng.next_u32() % (buffer.len() as u32 - 7)) as u16 + 1;

        let space_packet = SpacePacket::assemble(
            &mut buffer,
            packet_type,
            secondary_header_flag,
            apid,
            sequence_flag,
            sequence_count,
            packet_data_length,
        )
        .unwrap();

        assert_eq!(
            packet_type,
            space_packet.packet_type(),
            "Serialized packet type ({:?}) does not match with final deserialized packet type ({:?}) for packet ({:?})",
            packet_type,
            space_packet.packet_type(),
            space_packet
        );

        assert_eq!(
            secondary_header_flag,
            space_packet.secondary_header_flag(),
            "Serialized secondary header flag ({:?}) does not match with final deserialized secondary header flag ({:?}) for packet ({:?})",
            secondary_header_flag,
            space_packet.secondary_header_flag(),
            space_packet
        );

        assert_eq!(
            apid,
            space_packet.apid(),
            "Serialized APID ({:?}) does not match with final deserialized APID ({:?}) for packet ({:?})",
            apid,
            space_packet.apid(),
            space_packet
        );

        assert_eq!(
            sequence_flag,
            space_packet.sequence_flag(),
            "Serialized sequence flag ({:?}) does not match with final deserialized sequence flag ({:?}) for packet ({:?})",
            sequence_flag,
            space_packet.sequence_flag(),
            space_packet
        );

        assert_eq!(
            sequence_count,
            space_packet.packet_sequence_count(),
            "Serialized sequence count ({:?}) does not match with final deserialized sequence count ({:?}) for packet ({:?})",
            sequence_count,
            space_packet.packet_sequence_count(),
            space_packet
        );

        assert_eq!(
            packet_data_length as usize,
            space_packet.packet_data_length(),
            "Serialized packet type ({:?}) does not match with final deserialized packet type ({:?}) for packet ({:?})",
            packet_data_length,
            space_packet.packet_data_length(),
            space_packet
        );
    }
}

/// Empty packet data fields are not permitted by CCSDS 133.0-B-2, so such requests must be
/// rejected.
#[test]
fn empty_packet_data_field() {
    let mut bytes = [0u8; 7];
    let result = SpacePacket::assemble(
        &mut bytes,
        PacketType::Telemetry,
        SecondaryHeaderFlag::Present,
        Apid::new(0),
        SequenceFlag::Unsegmented,
        PacketSequenceCount(0),
        0,
    );
    assert_eq!(
        result,
        Err(SpacePacketAssemblyError::EmptyDataFieldRequested)
    );
}

/// When the buffer to construct a Space Packet in is too small to contain a packet primary header,
/// this shall be caught and an error shall be returned, independent of the actual packet request.
#[test]
fn buffer_too_small_for_header_construction() {
    let mut buffer = [0u8; 5];
    let buffer_length = buffer.len();
    let result = SpacePacket::assemble(
        &mut buffer,
        PacketType::Telemetry,
        SecondaryHeaderFlag::Present,
        Apid::new(0),
        SequenceFlag::Unsegmented,
        PacketSequenceCount(0),
        1,
    );
    assert_eq!(
        result,
        Err(SpacePacketAssemblyError::BufferTooSmall {
            buffer_length,
            packet_length: 7
        })
    );
}

/// When the buffer to construct a Space Packet in is too small to contain the full packet, an
/// error shall be returned stating as such.
#[test]
fn buffer_too_small_for_packet_construction() {
    use rand::{RngCore, SeedableRng};
    // Note that we always use the same seed for reproducibility.
    let mut rng = rand::rngs::SmallRng::seed_from_u64(42);
    let mut buffer = [0u8; 128];
    let buffer_length = buffer.len();

    for _ in 0..1000 {
        // Generate a pseudo-random packet data length between 128 and u16::MAX.
        let packet_data_length = (rng.next_u32() % (u16::MAX - 128) as u32) as u16 + 128;
        let result = SpacePacket::assemble(
            &mut buffer,
            PacketType::Telemetry,
            SecondaryHeaderFlag::Present,
            Apid::new(0),
            SequenceFlag::Unsegmented,
            PacketSequenceCount(0),
            packet_data_length,
        );
        assert_eq!(
            result,
            Err(SpacePacketAssemblyError::BufferTooSmall {
                buffer_length,
                packet_length: packet_data_length as usize + SpacePacket::primary_header_size(),
            })
        );
    }
}

/// When the buffer to parse a packet from is too small, an error shall be returned to indicate
/// this.
#[test]
fn buffer_too_small_for_parsed_packet() {
    use rand::{RngCore, SeedableRng};
    // Note that we always use the same seed for reproducibility.
    let mut rng = rand::rngs::SmallRng::seed_from_u64(42);
    let mut buffer = [0u8; 256];

    for _ in 0..1000 {
        // Generate a pseudo-random packet data length between 128 and 250, so that the resulting
        // packet will fit on a 256-byte buffer.
        let packet_data_length = (rng.next_u32() % 128) as u16 + 122;

        // Construct a valid Space Packet.
        let packet = SpacePacket::assemble(
            &mut buffer,
            PacketType::Telemetry,
            SecondaryHeaderFlag::Present,
            Apid::new(0),
            SequenceFlag::Unsegmented,
            PacketSequenceCount(0),
            packet_data_length,
        )
        .unwrap();

        // Subsequently, truncate the resulting byte sequence to 127 bytes, so that it will always
        // be invalid (the stored packet data length will always correspond with a packet larger
        // than 127 bytes).
        let bytes = &packet.as_bytes()[..127];
        let result = SpacePacket::extract(bytes);
        assert_eq!(
            result,
            Err(InvalidSpacePacket::PartialPacket {
                packet_size: packet_data_length as usize + SpacePacket::primary_header_size(),
                buffer_size: bytes.len()
            })
        );
    }
}
