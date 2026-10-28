# Requirements traceability

This document traces each normative requirement of CCSDS 133.0-B-2, *Space Packet Protocol* (Blue Book, issue 2, June 2020, including editorial changes 1 and 2), to the tests and formal proofs that verify it in this crate.

This crate implements the Space Packet Protocol data unit (section 4.1): parsing, validating and constructing Space Packets. It does not implement an SPP protocol entity: the Packet and Octet String services (section 3), the sending and receiving end procedures (sections 4.2 and 4.3) and management (section 5) are left to the user. Requirements on those parts, and requirements on mission-specific contents such as the secondary header, are listed as out of scope, each with the reason.

## How to read this matrix

- **Clause**: the numbered clause of CCSDS 133.0-B-2. Sections that are out of scope as a whole are listed once, by their section number.
- **Status**: *Tested* means that the listed items verify the requirement. *Out of scope* means that the requirement does not apply to this crate; the last column then gives the reason.
- **Verified by**: the unit tests (in `src/lib.rs`, module `tests`, run with `cargo test`) and Kani proofs, marked *(Kani)* (in `src/lib.rs`, module `kani_harness`, run with `cargo kani`). A Kani proof covers all possible inputs within its stated bounds, not just sample values.

Every listed test also states the clauses it verifies in its doc comment, as a `Requirements:` line. The test `every_requirement_is_traced` in `tests/traceability.rs` checks that this matrix, those annotations and the list of clauses in the standard agree. When adding or changing a test, update both its annotation and this matrix.

## Matrix

| Clause | Requirement (paraphrased) | Status | Verified by |
|---|---|---|---|
| 1.6.3 | Bit 0 of a field is transmitted first and is its most significant bit; octets are numbered from zero. (The primary header contains no spare bits.) | Tested | `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 3.2.2.1 | A Space Packet is a delimited, octet-aligned data unit of at least 7 and at most 65542 octets. | Tested | `roundtrip`, `empty_packet_data_field`, `buffer_too_small_for_header_construction`, `buffer_too_large_for_construction`, `packet_parsing` (Kani), `packet_construction` (Kani) |
| 3.2.2.2 | The SPP user shall use the Packet Service to transfer Space Packets. | Out of scope | Obligation on users of an SPP service provider; this crate provides the PDU, not the service. |
| 3.2.3 | Octet String SDU: 1 to 65536 octets, may contain a secondary header, placed in the User Data Field of a single packet, transferred through the Octet String Service. | Out of scope | The Octet String Service is not implemented. The equivalent 1 to 65536 octet bound on the packet data field is verified under 4.1.2.1. |
| 3.3 | Packet Service: overview, parameters (Space Packet, APID, Packet Loss Indicator, QoS Requirement) and the PACKET.request / PACKET.indication primitives. | Out of scope | Service primitives belong to a protocol entity, which this crate does not implement. `SpacePacket::parse` and `SpacePacket::construct` are building blocks for one. |
| 3.4 | Octet String Service: overview, parameters (Octet String, APID, Secondary Header Indicator, Data Loss Indicator) and the OCTET_STRING.request / OCTET_STRING.indication primitives. | Out of scope | The Octet String Service is not implemented. |
| 4.1.2.1 | A Space Packet consists of a 6-octet Packet Primary Header followed contiguously by a Packet Data Field of 1 to 65536 octets. | Tested | `deserialize_trivial_packet`, `serialize_trivial_packet`, `roundtrip`, `empty_packet_data_field`, `buffer_too_large_for_construction`, `primary_header_layout`, `packet_parsing` (Kani) |
| 4.1.2.2 | A Space Packet consists of at least 7 and at most 65542 octets. | Tested | `roundtrip`, `empty_packet_data_field`, `buffer_too_small_for_header_construction`, `buffer_too_large_for_construction`, `packet_parsing` (Kani), `packet_construction` (Kani) |
| 4.1.3.1 | The primary header consists of the Packet Version Number (3 bits), Packet Identification (13 bits), Packet Sequence Control (16 bits) and Packet Data Length (16 bits), contiguously and in that order. | Tested | `primary_header_layout`, `header_setters_are_independent` (Kani) |
| 4.1.3.2.1 | Bits 0-2 contain the Packet Version Number. | Tested | `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.2.2 | The Packet Version Number identifies a Space Packet of this standard and is set to '000'. | Tested | `serialize_trivial_packet`, `primary_header_from_partial_packet`, `primary_header_layout`, `unsupported_packet_versions_rejected`, `header_parsing` (Kani), `header_encoding` (Kani) |
| 4.1.3.3.1.1 | Bits 3-15 contain the Packet Identification Field. | Tested | `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.3.1.2 | The Packet Identification Field consists of the Packet Type (1 bit), Secondary Header Flag (1 bit) and APID (11 bits). | Tested | `primary_header_layout`, `header_setters_are_independent` (Kani) |
| 4.1.3.3.2.1 | Bit 3 contains the Packet Type. | Tested | `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.3.2.2 | The Packet Type distinguishes telemetry (reporting) packets from telecommand (requesting) packets. | Tested | `primary_header_layout` |
| 4.1.3.3.2.3 | The Packet Type is '0' for telemetry and '1' for telecommand. | Tested | `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.3.3.1 | Bit 4 contains the Secondary Header Flag. | Tested | `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.3.3.2 | The Secondary Header Flag is '1' if a Packet Secondary Header is present and '0' otherwise. | Tested | `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.3.3.3 | The Secondary Header Flag is static per APID and managed data path throughout a Mission Phase. | Out of scope | A constraint on mission configuration over time, which cannot be checked on individual packets. |
| 4.1.3.3.3.4 | The Secondary Header Flag is '0' for Idle Packets. | Tested | `idle_packet_with_secondary_header_construction`, `setters_preserve_validity`, `header_parsing` (Kani), `packet_construction` (Kani) |
| 4.1.3.3.4.1 | Bits 5-15 contain the APID. | Tested | `apid_conversion`, `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.3.4.2 | The APID provides the naming mechanism for the managed data path. | Out of scope | The meaning of APIDs is mission-specific; the crate carries the value only. |
| 4.1.3.3.4.3 | The APID may uniquely identify the sending or receiving application process. | Out of scope | Permissive clause ('may'): there is no behaviour to verify. |
| 4.1.3.3.4.4 | The APID of Idle Packets is all ones ('11111111111'). | Tested | `apid_conversion`, `header_parsing` (Kani) |
| 4.1.3.4.1.1 | Bits 16-31 contain the Packet Sequence Control Field. | Tested | `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.4.1.2 | The Packet Sequence Control Field consists of the Sequence Flags (2 bits) and the Packet Sequence Count or Packet Name (14 bits). | Tested | `primary_header_layout`, `header_setters_are_independent` (Kani) |
| 4.1.3.4.2.1 | Bits 16-17 contain the Sequence Flags. | Tested | `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.4.2.2 | The Sequence Flags are '00' for a continuation segment, '01' for the first segment, '10' for the last segment and '11' for unsegmented user data. | Tested | `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.4.2.3 | If the Octet String Service is used anywhere in the managed data path, the Sequence Flags are '11'. | Out of scope | Applies to the Octet String Service, which is not implemented. |
| 4.1.3.4.3.1 | Bits 18-31 contain the Packet Sequence Count or Packet Name. | Tested | `packet_sequence_count_conversion`, `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.4.3.2 | Telemetry packets carry a Packet Sequence Count; telecommand packets carry a Packet Sequence Count or a Packet Name. | Out of scope | Which of the two the field holds is the user's choice; the crate stores any 14-bit value, as verified under 4.1.3.4.3.1. |
| 4.1.3.4.3.3 | The Packet Sequence Count is a sequential binary count per user application (APID), not shared across APIDs. | Out of scope | Per-APID counter state is kept by the user application. The crate provides `PacketSequenceCount`, whose counting is verified under 4.1.3.4.3.4. |
| 4.1.3.4.3.4 | The Packet Sequence Count is continuous modulo 16384. | Tested | `packet_sequence_count_wraps`, `sequence_count_increment` (Kani) |
| 4.1.3.5.1 | Bits 32-47 contain the Packet Data Length. | Tested | `primary_header_layout`, `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.3.5.2 | The Packet Data Length contains a length count C that is one fewer than the length in octets of the Packet Data Field. | Tested | `buffer_too_small_for_parsed_packet`, `parse_back_to_back_packets`, `primary_header_layout`, `header_encoding` (Kani) |
| 4.1.3.5.3 | C = (total number of octets in the Packet Data Field) - 1. | Tested | `deserialize_trivial_packet`, `roundtrip`, `primary_header_layout`, `packet_parsing` (Kani), `header_encoding` (Kani), `header_decoding` (Kani) |
| 4.1.4.1.1 | The Packet Data Field consists of a Packet Secondary Header and/or a User Data Field, contiguously and in that order. | Out of scope | The internal structure of the packet data field is mission-specific and opaque to the crate. |
| 4.1.4.1.2 | The Packet Data Field contains at least one octet. | Tested | `empty_packet_data_field`, `packet_parsing` (Kani), `packet_construction` (Kani) |
| 4.1.4.2 | Packet Secondary Header: placement, presence rules, Time Code Field and Ancillary Data Field formats. | Out of scope | Secondary header contents are mission-specific and managed. Whether one is mandatory (no User Data Field) cannot be determined without knowing that format. Its prohibition for Idle Packets is verified under 4.1.3.3.3.4. |
| 4.1.4.3 | User Data Field: placement, presence rules, octet alignment and contents (application data, or Idle Data for Idle Packets). | Out of scope | User data contents are opaque to the crate; it gives access to the whole packet data field through `SpacePacket::packet_data_field`. |
| 4.2 | Sending end protocol procedures: Packet Assembly Function (including maintaining a sequence counter) and Packet Transfer Function (multiplexing and transfer). | Out of scope | The sending end protocol entity is not implemented. `SpacePacket::construct` and `PacketSequenceCount::increment` are building blocks for one. |
| 4.3 | Receiving end protocol procedures: Packet Extraction Function (including data loss detection) and Packet Reception Function (demultiplexing and delivery). | Out of scope | The receiving end protocol entity is not implemented. `SpacePacket::parse` and `SpacePackets` are building blocks for one. |
| 5.2 | Managed protocol configuration parameters: maximum packet length, multiplexing scheme, service type and secondary header contents. | Out of scope | Managed parameters are set by the mission's management system. |
| A2 | Protocol Implementation Conformance Statement (PICS) requirements list. | Out of scope | A PICS is completed for a full SPP implementation. This matrix supplies the evidence for its protocol data unit items SPP-14 to SPP-16. |
