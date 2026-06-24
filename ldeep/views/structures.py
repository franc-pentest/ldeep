import struct
from dataclasses import dataclass


@dataclass
class MSDS_MANAGEDPASSWORD_BLOB:
    """MS-ADTS gMSA managed password blob."""

    _HEADER = struct.Struct("<HHLHHHH")  # Version, Reserved, Length + 4 offsets

    version: int
    reserved: int
    length: int
    current_password: bytes
    previous_password: bytes | None
    query_password_interval: bytes
    unchanged_password_interval: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "MSDS_MANAGEDPASSWORD_BLOB":
        version, reserved, length, cur_off, prev_off, query_off, unchanged_off = (
            cls._HEADER.unpack_from(data)
        )

        cur_end = query_off if prev_off == 0 else prev_off
        return cls(
            version,
            reserved,
            length,
            current_password=data[cur_off:cur_end],
            previous_password=(data[prev_off:query_off] if prev_off else None),
            query_password_interval=data[query_off:unchanged_off],
            unchanged_password_interval=data[unchanged_off:],
        )
