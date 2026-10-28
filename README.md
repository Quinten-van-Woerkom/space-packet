# Space Packet
Simple and generic Rust implementation of the Consultative Committee for Space Data Systems (CCSDS) Space Packet Protocol, as defined in CCSDS 133.0-B-2.
Written to be fully `no_std` and without `unsafe` blocks: this makes it suitable for usage in high-assurance embedded environments.
The Kani model checker is used to formally prove the absence of certain classes of errors: parsing of byte sequences and creation of Space Packets shall succeed for all possible inputs without panicking. Violation of preconditions shall be handled gracefully by returning an error.

Each requirement of CCSDS 133.0-B-2 is traced to the tests and proofs that verify it, or to the reason it is out of scope for this crate, in `TRACEABILITY.md`. The same matrix is included in the API documentation, as the `traceability` module.

## Usage
Reading Space Packets from some given byte buffer may be done as follows:
```rust
use space_packet::*;
// Constructs a simple packet with pre-determined values.
let bytes = &[
    0b0001_1000u8, // Packet version 0, telecommand packet
    0b0000_0000u8, // APID 0
    0b1100_0000u8, // Unsegmented packet
    0b0000_0000u8, // Packet sequence count 0
    0b0000_0000u8, // Packet data length 1
    0b0000_0000u8,
    0b0000_0000u8, // One-byte data field
];
// Parses the given byte buffer into a fully type-safe wrapper struct. No copies are made, the
// returned struct is a direct, type-safe view into the byte buffer.
let packet = SpacePacket::parse(bytes).unwrap();
// Check that the packet contains the expected values.
assert_eq!(packet.packet_version(), PacketVersionNumber::version1_ccsds_packet());
assert_eq!(packet.packet_type(), PacketType::Telecommand);
assert_eq!(packet.apid(), Apid::new(0));
assert_eq!(packet.sequence_flag(), SequenceFlag::Unsegmented);
assert_eq!(packet.packet_sequence_count(), PacketSequenceCount::new());
assert_eq!(packet.packet_data_length(), 1);
assert_eq!(packet.packet_data_field(), &[0b0000_0000u8]);
```
Note the use of accessor functions to conveniently read off the Space Packet primary header fields. Rather than raw bytes, typed wrappers are returned to represent the stored header data.

Vice versa, Space Packets may be constructed directly on a pre-allocated byte buffer.
```rust
use space_packet::*;
// A pre-allocated buffer must be used.
let buffer = &mut [0u8; 128];
// Construction happens in-place on this buffer: a `SpacePacket` is returned, or an appropriate
// error to indicate construction failure.
let packet = SpacePacket::construct(
    buffer[..14].as_mut(),
    PacketType::Telemetry,
    SecondaryHeaderFlag::Absent,
    Apid::new(42),
    SequenceFlag::Unsegmented,
    PacketSequenceCount::new(),
).unwrap();
// Initializes the packet data field with some arbitrary values.
for (index, byte) in packet.packet_data_field_mut().iter_mut().enumerate() {
    *byte = index as u8;
}
// The returned packet may be queried for its header fields.
assert_eq!(packet.packet_version(), PacketVersionNumber::version1_ccsds_packet());
assert_eq!(packet.packet_type(), PacketType::Telemetry);
assert_eq!(packet.apid(), Apid::new(42));
assert_eq!(packet.sequence_flag(), SequenceFlag::Unsegmented);
assert_eq!(packet.packet_sequence_count(), PacketSequenceCount::new());
assert_eq!(packet.packet_data_length(), 8);
assert_eq!(packet.packet_data_field(), &[0u8, 1, 2, 3, 4, 5, 6, 7]);
```

This crate strictly follows the CCSDS Space Packet Protocol standard: not all byte sequences are valid Space Packets. In such cases, an appropriate error is returned to the caller, such that they can determine the appropriate course of action. This applies both to parsing and construction of Space Packets: once a `SpacePacket` is obtained, it must be a semantically valid Space Packet. Examples of failure cases:
```rust
use space_packet::*;

// This Space Packet stores a packet data length of 8 bytes, which cannot actually be contained in
// this byte buffer. Either the packet is incomplete, or it is erroneous.
let bytes = &[
    0b0001_1000u8,
    0b0000_0000u8,
    0b1100_0000u8,
    0b0000_0000u8,
    0b0000_0000u8,
    7u8,           // Packet data length 8
    0b0000_0000u8, // One-byte data field
];
// Returns an error indicating that the given byte slice contains only a partial packet.
let result = SpacePacket::parse(bytes);
assert_eq!(result, Err(InvalidSpacePacket::PartialPacket { packet_size: 14, buffer_size: 7 }));

// This Space Packet is an idle packet; such packets may not contain a secondary header field.
let bytes = &[
    0b0001_1111u8, // Secondary header flag is 1,
    0b1111_1111u8, // but APID is 'all ones' (idle)
    0b1100_0000u8,
    0b0000_0000u8,
    0b0000_0000u8,
    0b0000_0000u8,
    0b0000_0000u8,
];
// Returns an error indicating that idle packets may not contain a secondary header.
let result = SpacePacket::parse(bytes);
assert_eq!(result, Err(InvalidSpacePacket::IdlePacketWithSecondaryHeader));

// Requesting such a packet during construction is rejected in the same manner.
let buffer = &mut [0u8; 8];
let result = SpacePacket::construct(
    buffer,
    PacketType::Telemetry,
    SecondaryHeaderFlag::Present,
    Apid::IDLE,
    SequenceFlag::Unsegmented,
    PacketSequenceCount::new(),
);
assert_eq!(result, Err(InvalidPacketConstruction::IdlePacketWithSecondaryHeader));
```

The only ways to obtain a `SpacePacket` are through these validating constructors, and a `SpacePacket` may only be modified in ways that keep it valid. In particular, its packet data field is always exactly as long as its packet data length field states.

## Packet streams
Packets that are stored back-to-back may be parsed one at a time using `SpacePacket::parse_prefix`, which also returns the bytes following the packet, or iterated over using `SpacePackets`:
```rust
use space_packet::*;
let bytes = &[
    0b0000_0000u8, 0b0000_0001u8, 0b1100_0000u8, 0b0000_0000u8, 0b0000_0000u8, 0b0000_0000u8,
    0xaau8,        // First packet, APID 1, one-byte data field
    0b0000_0000u8, 0b0000_0010u8, 0b1100_0000u8, 0b0000_0000u8, 0b0000_0000u8, 0b0000_0001u8,
    0xbbu8, 0xccu8, // Second packet, APID 2, two-byte data field
    0b0000_0000u8, 0b0000_0011u8, // Start of a third packet, not yet fully received
];
let mut packets = SpacePackets::new(bytes);
assert_eq!(packets.next().unwrap().unwrap().apid(), Apid::new(1));
assert_eq!(packets.next().unwrap().unwrap().packet_data_field(), &[0xbb, 0xcc]);
// The partial packet results in an error, after which iteration stops. Its bytes remain
// available, for example to be completed once the rest of the packet has been received.
assert!(packets.next().unwrap().is_err());
assert!(packets.next().is_none());
assert_eq!(packets.remainder(), &[0b0000_0000u8, 0b0000_0011u8]);
```