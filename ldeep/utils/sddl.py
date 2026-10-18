#!/usr/bin/env python3

"""
A module used to handle binary ntSecurityDescriptor from Active Directory LDAP.
"""

from struct import unpack

from ldap3.protocol.formatters.formatters import format_sid, format_uuid_le

from ldeep.utils import format_bitmask
from ldeep.views.constants import (
    ACCESS_MASK,
    ACCESS_MASK_COMPOSITES,
    ACE_FLAGS,
    ACE_OBJECT_FLAGS,
    EXTENDED_RIGHTS_MAP,
    SCHEMA_GUIDS_MAP,
    SD_CONTROL_FLAGS,
    WELL_KNOWN_DOMAIN_RIDS,
    WELL_KNOWN_SIDS,
)

SDDLTypeFlags = {
    "Self Relative": 0b1000000000000000,
    "RM Control Valid": 0b0100000000000000,
    "SACL Protected": 0b0010000000000000,
    "DACL Protected": 0b0001000000000000,
    "SACL Auto Inherit": 0b0000100000000000,
    "DACL Auto Inherit": 0b0000010000000000,
    "SACL Auto Inherit Required": 0b0000001000000000,
    "DACL Auto Inherit Required": 0b0000000100000000,
    "Server Security": 0b0000000010000000,
    "DACL Trusted": 0b0000000001000000,
    "SACL Defaulted": 0b0000000000100000,
    "SACL Present": 0b0000000000010000,
    "DACL Defaulted": 0b0000000000001000,
    "DACL Present": 0b0000000000000100,
    "Group Defaulted": 0b0000000000000010,
    "Owner Defaulted": 0b0000000000000001,
}

SID_SIZE = 28

ADS_RIGHT_DS_SELF = 0x00000008
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100


def parse_ntSecurityDescriptor(input_buffer):
    """Parses a ntSecurityDescriptor."""
    out = dict()
    fields = (
        "Revision",
        "Raw Type",
        "Offset to owner SID",
        "Offset to group SID",
        "Offset to SACL",
        "Offset to DACL",
    )

    for k, v in zip(fields, unpack("<HHIIII", input_buffer[:20])):
        out[k] = v

    out["Type"] = parse_sddl_type(out["Raw Type"])

    for x in ("Owner", "Group"):
        offset = out["Offset to %s SID" % (x.lower())]
        out["%s SID" % x] = format_sid(input_buffer[offset : offset + SID_SIZE])

    if out["Type"]["SACL Present"]:
        out["SACL"] = parse_acl(input_buffer[out["Offset to SACL"] :])

    if out["Type"]["DACL Present"]:
        out["DACL"] = parse_acl(input_buffer[out["Offset to DACL"] :])

    del out["Offset to owner SID"]
    del out["Offset to group SID"]
    del out["Offset to SACL"]
    del out["Offset to DACL"]
    del out["Type"]

    return out


def resolve_flags(bfr, flags):
    """
    Helper to resolve flag values and names.

    Arguments:
            #bfr:integer
                    The buffer containing flags.
            #flags:dict
                    The dictionary of flag names and values.
    """
    return {k: v & bfr != 0 for k, v in flags.items()}


def parse_sddl_type(typeflags):
    """
    Parses SDDL Type flags.
    """
    return resolve_flags(typeflags, SDDLTypeFlags)


def parse_acl(input_buffer):
    """
    Parses ACL from SDDL.

    Returns a list of ACEs.
    """
    out = dict()
    fields = ("Revision", "Size", "Num ACEs")

    for k, v in zip(fields, unpack("<HHI", input_buffer[:8])):
        out[k] = v

    out["ACEs"] = parse_aces(input_buffer[8 : 8 + out["Size"]], out["Num ACEs"])
    return out


def parse_aces(input_buffer, count):
    """
    Parses the list of ACEs.
    """
    out = []
    while len(out) < count:
        ace = dict()
        fields = ("Raw Type", "Raw Flags", "Size", "Raw Access Required")
        for k, v in zip(fields, unpack("<BBHI", input_buffer[:8])):
            ace[k] = v

        ace["Type"] = parse_sddl_dacl_ace_type(ace["Raw Type"])

        offset = 8

        if ace["Type"].endswith("Object"):
            fields = ("Raw Object Flags",)
            for k, v in zip(fields, unpack("<I", input_buffer[8:12])):
                ace[k] = v
            ace["Object Flags"] = parse_ace_object_flags(ace["Raw Object Flags"])

            offset = 12
            if ace["Object Flags"]["Object Type Present"]:
                ace["GUID"] = format_uuid_le(input_buffer[offset : offset + 16])
                offset += 16
            if ace["Object Flags"]["Inherited Object Type Present"]:
                ace["Inherited GUID"] = format_uuid_le(
                    input_buffer[offset : offset + 16]
                )
                offset += 16

            ace["SID"] = format_sid(input_buffer[offset : ace["Size"]])

        ace["SID"] = format_sid(input_buffer[offset : ace["Size"]])

        input_buffer = input_buffer[ace["Size"] :]

        out.append(ace)
    return out


ACEObjectFlags = {
    "Object Type Present": 0b00000000000000000000000000000001,
    "Inherited Object Type Present": 0b00000000000000000000000000000010,
}


def parse_ace_object_flags(input_buffer):
    """
    Parses flags in an ACE containing an object.
    """
    return resolve_flags(input_buffer, ACEObjectFlags)


ACEType = {
    0x00: "Access Allowed",
    0x01: "Access Denied",
    0x02: "System Audit",
    0x03: "System Alarm",
    0x04: "Access Allowed Compound",
    0x05: "Access Allowed Object",
    0x06: "Access Denied Object",
    0x07: "System Audit Object",
    0x08: "System Alarm Object",
    0x09: "Access Allowed Callback",
    0x0A: "Access Denied Callback",
    0x0B: "Access Allowed Callback Object",
    0x0C: "Access Denied Callback Object",
    0x0D: "System Audit Callback",
    0x0E: "System Alarm Callback",
    0x0F: "System Audit Callback Object",
    0x10: "System Alarm Callback Object",
    0x11: "System Mandatory Label",
    0x12: "System Resource Attribute",
    0x13: "System Scoped Policy ID",
}


def parse_sddl_dacl_ace_type(ace_type):
    """
    Parses the type of an ACE.
    """
    return ACEType[ace_type]


def resolve_sid_name(sid):
    """
    Return the name of a well-known SID (universal or domain relative), else the SID itself.
    """
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]
    if sid.startswith("S-1-5-21-"):
        try:
            rid = int(sid.rsplit("-", 1)[1])
        except ValueError:
            return sid
        return WELL_KNOWN_DOMAIN_RIDS.get(rid, sid)
    return sid


def resolve_guid_name(guid, schema_guids, rights_guids, prefer_rights=False):
    """
    Return the name of a schema object or extended right GUID, else the GUID itself.

    Validated writes share their GUID with the attribute they protect, hence
    `prefer_rights` to choose which name to display first.
    """
    key = guid.strip("{}").lower()
    maps = (
        (rights_guids, schema_guids) if prefer_rights else (schema_guids, rights_guids)
    )
    for guid_map in maps:
        if key in guid_map:
            return guid_map[key]
    return guid


def format_access_mask(mask):
    """
    Return a human readable access mask.
    """
    if mask in ACCESS_MASK_COMPOSITES:
        return ACCESS_MASK_COMPOSITES[mask]
    return format_bitmask(mask, ACCESS_MASK, 32)


def format_ace(ace, schema_guids, rights_guids):
    """
    Return a human readable copy of an ACE parsed by `parse_aces`.
    """
    # Already formatted
    if "Raw Type" not in ace:
        return ace

    mask = ace["Raw Access Required"]
    out = {
        "Type": ace["Type"],
        "Size": ace["Size"],
        "Flags": format_bitmask(ace["Raw Flags"], ACE_FLAGS, 8),
        "Access Required": format_access_mask(mask),
        "SID": resolve_sid_name(ace["SID"]),
    }
    if "Raw Object Flags" in ace:
        out["Object Flags"] = format_bitmask(
            ace["Raw Object Flags"], ACE_OBJECT_FLAGS, 32
        )
    if "GUID" in ace:
        # ExtendedRight and Self GUIDs are control access rights, others are schema objects
        prefer_rights = bool(mask & (ADS_RIGHT_DS_CONTROL_ACCESS | ADS_RIGHT_DS_SELF))
        out["GUID"] = resolve_guid_name(
            ace["GUID"], schema_guids, rights_guids, prefer_rights
        )
    if "Inherited GUID" in ace:
        out["Inherited GUID"] = resolve_guid_name(
            ace["Inherited GUID"], schema_guids, rights_guids
        )
    return out


def format_ntSecurityDescriptor(
    sd, schema_guids=SCHEMA_GUIDS_MAP, rights_guids=EXTENDED_RIGHTS_MAP
):
    """
    Return a human readable copy of a ntSecurityDescriptor parsed by `parse_ntSecurityDescriptor`.

    Raw values are replaced by flag names, and SIDs and GUIDs by their names when known.
    """
    if not isinstance(sd, dict):
        return sd

    out = dict(sd)
    if "Raw Type" in out:
        out["Control"] = format_bitmask(out.pop("Raw Type"), SD_CONTROL_FLAGS, 16)
    for x in ("Owner SID", "Group SID"):
        if x in out:
            out[x] = resolve_sid_name(out[x])
    for x in ("DACL", "SACL"):
        if x in out:
            out[x] = dict(out[x])
            out[x]["ACEs"] = [
                format_ace(ace, schema_guids, rights_guids) for ace in out[x]["ACEs"]
            ]
    return out
