#![no_std]
//! Generic implementation of the CCSDS 133.0-B-2 Space Packet Protocol (SPP). That is, this crate
//! concerns itself only with parsing and construction of CCSDS Space Packets, as that is
//! independent of the precise implementation. Endpoint functionality, i.e., actually consuming and
//! responding to the packet contents is implementation specific, and hence out of scope.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Space packets are implemented as dynamically-sized structs that contain the primary header as
/// their first field, followed by the packet data as pure byte array. In this manner,
/// deserialization can be reduced to a simple byte cast followed by interpretation of the primary
/// header - without any data copies needed. This is useful for high-throughput applications, and
/// ensures that no allocation or significant additional memory is needed to consume space packets.
///
/// This does also mean that space packets may only be handled by reference. In the context of this
/// crate that helps enforce that no spurious copies can be made of the user data (which may be
/// rather large and would incur additional allocations), albeit at the cost of some convenience.
///
/// Any means of constructing a SpacePacket in this crate shall perform a consistency check on any
/// received bytes. Hence, any SpacePacket object may be assumed to be a valid Space Packet.
#[repr(C)]
#[derive(Eq, PartialEq, Debug, Hash, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct SpacePacket {
    bytes: [u8],
}

impl SpacePacket {
    /// Attempts to parse a space packet from a given byte slice. If this fails, a reason is
    /// given for this failure. Shall never panic: rather, an error enum is returned explaining why
    /// the given octet string is not a valid space packet.
    #[cfg_attr(test, no_panic::no_panic)]
    pub fn parse(bytes: &[u8]) -> Result<&SpacePacket, SpacePacketParsingError> {
        // First, we verify that the slice has sufficient size to actually contain a space packet
        // primary header.
        let length = bytes.len();
        if length < Self::primary_header_size() {
            return Err(SpacePacketParsingError::SliceTooSmallForSpacePacketHeader { length });
        }

        // Afterwards, we know that it is possible to read a full six-byte primary header from this
        // byte slice, so we can construct a space packet by bytecasting. Note that we must still
        // verify that the resulting space packet is well-formed, i.e., that its header contents
        // are valid.
        let primary_header: &SpacePacket = zerocopy::transmute_ref!(bytes);

        // Then, we verify that it is semantically correct.
        // If the packet version is not supported, the raw bytes are returned: after all, for different
        // packet versions, the "version 0" space packet structure need not be adhered to.
        let version = primary_header.packet_version();
        if !version.is_supported() {
            return Err(SpacePacketParsingError::UnsupportedPacketVersion { version });
        }

        // The packet header contains an indication of the actual amount of bytes stored in the packet.
        // If this is larger than the size of the slice, something went wrong.
        let length_from_header = primary_header.packet_data_length();
        let maximum_length_from_slice = bytes.len() - Self::primary_header_size();
        if length_from_header > maximum_length_from_slice {
            return Err(SpacePacketParsingError::SliceTooSmallForDataField {
                length_from_header,
                maximum_length_from_slice,
            });
        }

        // Afterwards, we may truncate the packet length as per the data field length given in the
        // packet primary header.
        let packet_size = length_from_header + Self::primary_header_size();
        let packet_bytes = &bytes[..packet_size];
        let packet: &SpacePacket = zerocopy::transmute_ref!(packet_bytes);

        Ok(packet)
    }

    /// Constructs a Space Packet in-place on a given buffer. May return a
    /// `SpacePacketConstructionError` if this is not possible for whatever reason. Note that the
    /// data field is only "allocated" on the buffer, but never further populated. That may be done
    /// after the SpacePacket is otherwise fully constructed.
    #[cfg_attr(test, no_panic::no_panic)]
    pub fn construct(
        buffer: &mut [u8],
        packet_type: PacketType,
        secondary_header_flag: SecondaryHeaderFlag,
        apid: Apid,
        sequence_flag: SequenceFlag,
        sequence_count: PacketSequenceCount,
        packet_data_length: u16,
    ) -> Result<&mut SpacePacket, SpacePacketConstructionError> {
        // Construction may fail if the buffer passed by the caller is not large enough to contain
        // a space packet with the requested data field length. We check this before doing any
        // other work.
        let buffer_length = buffer.len();
        let packet_length = SpacePacket::primary_header_size() as u32 + packet_data_length as u32;
        // In the rather esoteric case that the requested packet length is larger than the word size,
        // we must also correctly handle this cast.
        let packet_length_usize: usize =
            packet_length
                .try_into()
                .or(Err(SpacePacketConstructionError::BufferTooSmall {
                    buffer_length,
                    packet_length,
                }))?;
        if packet_length_usize > buffer_length {
            return Err(SpacePacketConstructionError::BufferTooSmall {
                buffer_length,
                packet_length,
            });
        }

        // As per the CCSDS Space Packet Protocol standard, we must reject requests for data field
        // lengths of zero.
        if packet_data_length == 0 {
            return Err(SpacePacketConstructionError::EmptyDataFieldRequested);
        }

        // Now that the buffer is known to be of sufficient size to store the requested space
        // packet, it may be transmuted into a reference to such a space packet.
        let packet: &mut SpacePacket = zerocopy::transmute_mut!(buffer);

        // Initialize header bytes to valid values.
        packet.set_apid(apid);
        packet.initialize_packet_version();
        packet.set_packet_type(packet_type);
        packet.set_secondary_header_flag(secondary_header_flag);
        packet.set_sequence_flag(sequence_flag);
        packet.set_packet_sequence_count(sequence_count);
        packet.set_packet_data_length(packet_data_length);

        Ok(packet)
    }

    /// Returns the size of a space packet primary header, in bytes. In the version that is
    /// presently implemented, that is always 6 bytes.
    pub const fn primary_header_size() -> usize {
        6
    }

    /// Since the space packet protocol may technically support alternative packet structures in
    /// future versions, the 3-bit packet version field may not actually contain a "correct" value.
    pub fn packet_version(&self) -> PacketVersionNumber {
        use core::ops::Shr;
        PacketVersionNumber(self.bytes[0].shr(5))
    }

    /// Initializes the packet version to the proper value. Must be a fixed value, so this function
    /// takes no arguments.
    pub fn initialize_packet_version(&mut self) {
        self.bytes[0] &= 0b0001_1111;
        self.bytes[0] |= PacketVersionNumber::version1_ccsds_packet().0 << 5;
    }

    /// The packet type denotes whether a packet is a telecommand (request) or telemetry (report)
    /// packet. Note that the exact definition of telecommand and telemetry may differ per system,
    /// and indeed the "correct" value here may differ per project.
    pub fn packet_type(&self) -> PacketType {
        match (self.bytes[0] & 0x10) == 0x10 {
            true => PacketType::Telecommand,
            false => PacketType::Telemetry,
        }
    }

    /// Sets the packet type to the given value.
    pub fn set_packet_type(&mut self, packet_type: PacketType) {
        self.bytes[0] &= 0b1110_1111;
        self.bytes[0] |= (packet_type as u8) << 4;
    }

    /// Denotes whether the packet contains a secondary header. If no user field is present, the
    /// secondary header is mandatory (presumably, to ensure that some data is always transferred,
    /// considering the space packet header itself contains no meaningful data).
    pub fn secondary_header_flag(&self) -> SecondaryHeaderFlag {
        match (self.bytes[0] & 0x08) == 0x08 {
            true => SecondaryHeaderFlag::Present,
            false => SecondaryHeaderFlag::Absent,
        }
    }

    /// Updates the value of the secondary header flag with the provided value.
    pub fn set_secondary_header_flag(&mut self, secondary_header_flag: SecondaryHeaderFlag) {
        self.bytes[0] &= 0b1111_0111;
        self.bytes[0] |= (secondary_header_flag as u8) << 3;
    }

    /// Returns the application process ID stored in the packet. The actual meaning of this APID
    /// field may differ per implementation: technically, it only represents "some" data path.
    /// In practice, it will often be a identifier for a data channel, the packet source, or the
    /// packet destination.
    pub fn apid(&self) -> Apid {
        let msb = self.bytes[0] & 0x07;
        let lsb = self.bytes[1];
        Apid(u16::from_be_bytes([msb, lsb]))
    }

    /// Sets the APID used to route the packet to the given value.
    pub fn set_apid(&mut self, apid: Apid) {
        let apid = apid.0.to_be_bytes();
        self.bytes[0] &= 0b1111_1000;
        self.bytes[0] |= apid[0] & 0b0000_0111;
        self.bytes[1] = apid[1];
    }

    /// Sequence flags may be used to indicate that the data contained in a packet is only part of
    /// a larger set of application data.
    pub fn sequence_flag(&self) -> SequenceFlag {
        use core::ops::Shr;
        match self.bytes[2].shr(6i32) {
            0b00 => SequenceFlag::Continuation,
            0b01 => SequenceFlag::First,
            0b10 => SequenceFlag::Last,
            0b11 => SequenceFlag::Unsegmented,
            _ => unreachable!("Internal error: Reached unreachable code segment"),
        }
    }

    /// Sets the sequence flag to the provided value.
    pub fn set_sequence_flag(&mut self, sequence_flag: SequenceFlag) {
        self.bytes[2] &= 0b0011_1111;
        self.bytes[2] |= (sequence_flag as u8) << 6;
    }

    /// The packet sequence count is unique per APID and denotes the sequential binary count of
    /// each space packet (generated per APID). For telecommands (i.e., with packet type 1) this
    /// may also be a "packet name" that identifies the telecommand packet within its
    /// communications session.
    pub fn packet_sequence_count(&self) -> PacketSequenceCount {
        let msb = self.bytes[2] & 0x3f;
        let lsb = self.bytes[3];
        PacketSequenceCount(u16::from_be_bytes([msb, lsb]))
    }

    /// Sets the packet sequence count to the provided value. This value must be provided by an
    /// external counter and is not provided at a Space Packet type level because it might differ
    /// between packet streams.
    pub fn set_packet_sequence_count(&mut self, sequence_count: PacketSequenceCount) {
        self.bytes[2] &= 0b1100_0000;
        self.bytes[2] |= sequence_count.0.to_be_bytes()[0] & 0b0011_1111;
        self.bytes[3] = sequence_count.0.to_be_bytes()[1];
    }

    /// The packet data length field represents the length of the associated packet data field.
    /// However, it is not stored directly: rather, the "length count" is stored, which is the
    /// packet data length minus one.
    pub fn packet_data_length(&self) -> usize {
        let count = u16::from_be_bytes([self.bytes[4], self.bytes[5]]);
        count as usize + 1
    }

    /// Sets the packet data length field to the provided value. Note that the given value is not
    /// stored directly, but rather decremented by one first. Accordingly, and as per the CCSDS
    /// Space Packet Protocol standard, packet data lengths of 0 are not allowed.
    pub fn set_packet_data_length(&mut self, packet_data_length: u16) {
        assert!(
            packet_data_length >= 1,
            "Packet data length must be at least one byte"
        );
        let stored_data_field_length = packet_data_length - 1;
        self.bytes[4] = stored_data_field_length.to_be_bytes()[0];
        self.bytes[5] = stored_data_field_length.to_be_bytes()[1];
    }

    /// Returns the total length of the packet in bytes. Note the distinction from the packet data
    /// length, which refers only to the length of the data field of the packet.
    pub fn packet_length(&self) -> usize {
        self.bytes.len()
    }

    /// Returns a reference to the packet data field contained in this space packet.
    pub fn packet_data_field(&self) -> &[u8] {
        &self.bytes[6..]
    }

    /// Returns a mutable reference to the packet data field contained in this space packet.
    pub fn packet_data_field_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[6..]
    }
}

/// Representation of the set of errors that may be encountered while deserializing a space packet.
/// Marked as non-exhaustive to permit extension with additional semantic errors in the future
/// without breaking API.
#[non_exhaustive]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum SpacePacketParsingError {
    /// Returned when a byte slice is too small to contain any space packet (i.e., is smaller than
    /// a header with a single-byte user data field).
    SliceTooSmallForSpacePacketHeader { length: usize },
    /// Returned when a slice does not have a known and supported packet version. For convenience,
    /// the packet version that is stored at the "conventional" (CCSDS packet version 0) is also
    /// returned, though it does not need to be meaningful in other packet versions.
    UnsupportedPacketVersion { version: PacketVersionNumber },
    /// Returned when a slice does not have sufficient bytes to contain the space packet with the
    /// length indicated in its header.
    SliceTooSmallForDataField {
        length_from_header: usize,
        maximum_length_from_slice: usize,
    },
}

/// Representation of the set of errors that may be encountered while constructing a space packet.
/// Marked as non-exhaustive to permit extension with additional semantic errors in the future
/// without breaking API.
#[non_exhaustive]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum SpacePacketConstructionError {
    /// Returned when the underlying buffer does not have sufficient bytes to contain a given space
    /// packet. The requested packet length is given as `u32` instead of `usize` to cover systems
    /// whose word size is smaller than `u32`. Because the requested space packet data field length
    /// may never exceed `u16::MAX`, a `u32` will cover all possible packet lengths.
    BufferTooSmall {
        buffer_length: usize,
        packet_length: u32,
    },
    /// As per the CCSDS standard, space packets shall have at least one byte in their data field.
    /// Hence, requests for an empty data field must be rejected.
    EmptyDataFieldRequested,
}

/// The packet version number represents the version of the space packet protocol that is used. In
/// the version presently implemented, this is defined to be zeroes.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct PacketVersionNumber(u8);

impl PacketVersionNumber {
    /// The space packet protocol version presently implemented in this crate is based on issue 2
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
pub enum PacketType {
    Telemetry = 0,
    Telecommand = 1,
}

/// Denotes whether the packet contains a secondary header. If no user field is present, the
/// secondary header is mandatory (presumably, to ensure that some data is always transferred,
/// considering the space packet header itself contains no meaningful data).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum SecondaryHeaderFlag {
    Absent = 0,
    Present = 1,
}

/// Returns the application process ID stored in the packet. The actual meaning of this APID
/// field may differ per implementation: technically, it only represents "some" data path.
/// In practice, it will often be a identifier for: a data channel, the packet source, or the
/// packet destination.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
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

    /// A special APID value (0x7ff) is reserved for idle space packets, i.e., packets that do not
    /// carry any actual data.
    pub fn is_idle(&self) -> bool {
        self.0 == 0x7ff
    }
}

/// Sequence flags may be used to indicate that the data contained in a packet is only part of
/// a larger set of application data.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub enum SequenceFlag {
    Continuation = 0b00,
    First = 0b01,
    Last = 0b10,
    #[default]
    Unsegmented = 0b11,
}

/// The packet sequence count is unique per APID and denotes the sequential binary count of
/// each space packet (generated per APID). For telecommands (i.e., with packet type 1) this
/// may also be a "packet name" that identifies the telecommand packet within its
/// communications session.
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct PacketSequenceCount(u16);

impl PacketSequenceCount {
    const MAX: u16 = 0b0011_1111_1111_1111u16;

    /// The packet sequence count is initialized to zero by default.
    pub fn new() -> Self {
        Self(0)
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
    let packet = SpacePacket::parse(bytes).unwrap();

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
    let packet = SpacePacket::construct(
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

/// Roundtrip serialization and subsequent deserialization of space packets shall result in exactly
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

        let space_packet = SpacePacket::construct(
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
    let result = SpacePacket::construct(
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
        Err(SpacePacketConstructionError::EmptyDataFieldRequested)
    );
}

/// When the buffer to construct a space packet in is too small to contain a packet primary header,
/// this shall be caught and an error shall be returned, independent of the actual packet request.
#[test]
fn buffer_too_small_for_header() {
    let mut buffer = [0u8; 5];
    let buffer_length = buffer.len();
    let result = SpacePacket::construct(
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
        Err(SpacePacketConstructionError::BufferTooSmall {
            buffer_length,
            packet_length: 7
        })
    );
}

/// When the buffer to construct a space packet in is too small to contain the full packet, an
/// error shall be returned stating as such.
#[test]
fn buffer_too_small_for_packet() {
    use rand::{RngCore, SeedableRng};
    // Note that we always use the same seed for reproducibility.
    let mut rng = rand::rngs::SmallRng::seed_from_u64(42);
    let mut buffer = [0u8; 128];
    let buffer_length = buffer.len();

    for _ in 0..1000 {
        let packet_data_length = (rng.next_u32() % (u16::MAX - 128) as u32) as u16 + 128;
        let result = SpacePacket::construct(
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
            Err(SpacePacketConstructionError::BufferTooSmall {
                buffer_length,
                packet_length: packet_data_length as u32
                    + (SpacePacket::primary_header_size() as u32),
            })
        );
    }
}
