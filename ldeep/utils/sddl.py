#!/usr/bin/env python3

"""
A module used to handle binary ntSecurityDescriptor from Active Directory LDAP.
"""

from struct import unpack
from ldap3.protocol.formatters.formatters import format_sid, format_uuid_le
from datetime import datetime, timezone
from calendar import timegm

from ldeep.views.constants import (
    WELLKNOWN_SIDS,
    ADRights,
    ObjectType,
    EdgeNames,
    ACE,
    ACEGuids,
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

        ace["Access Required"] = parse_ace_access(ace["Raw Access Required"])

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


ACEAccessFlags = {
    "Generic Read": 0b10000000000000000000000000000000,
    "Generic Write": 0b01000000000000000000000000000000,
    "Generic Execute": 0b00100000000000000000000000000000,
    "Generic All": 0b00010000000000000000000000000000,
    "Maximum Allowed": 0b00000010000000000000000000000000,
    "Access SACL": 0b00000000100000000000000000000000,
    "Synchronise": 0b00000000000100000000000000000000,
    "Write Owner": 0b00000000000010000000000000000000,
    "Write DAC": 0b00000000000001000000000000000000,
    "Read Control": 0b00000000000000100000000000000000,
    "Delete": 0b00000000000000010000000000000000,
    "Ads Control Access": 0b00000000000000000000000100000000,
    "Ads List Object": 0b00000000000000000000000010000000,
    "Ads Delete Tree": 0b00000000000000000000000001000000,
    "Ads Write Prop": 0b00000000000000000000000000100000,
    "Ads Read Prop": 0b00000000000000000000000000010000,
    "Ads Self Write": 0b00000000000000000000000000001000,
    "Ads List": 0b00000000000000000000000000000100,
    "Ads Delete Child": 0b00000000000000000000000000000010,
    "Ads Create Child": 0b00000000000000000000000000000001,
}


def parse_ace_access(input_buffer):
    """
    Parses access flags in an ACE.
    """
    return resolve_flags(input_buffer, ACEAccessFlags)


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


def getWindowsTimestamp(t: str) -> int:
    unix_timestamp = int(datetime.timestamp(t.replace(tzinfo=timezone.utc)))
    windows_timestramp = unix_timestamp + 11644473600
    return timegm(
        datetime.fromtimestamp(windows_timestramp - 11644473600).utctimetuple()
    )


def convertIsoTimestamp(t, field: str) -> int:
    """
    Convert Windows timestamp (100 ns since 1 Jan 1601) to
    unix timestamp.
    """
    if isinstance(t, str):
        if len(t) == 0:
            if field == "lastlogontimestamp":
                return -1
            else:
                return 0
    if str(t).startswith("1601-01-01"):
        return 0
    return int(t.timestamp())


def ace_has_Flags(value: int, ace_raw_flags: int) -> bool:
    return ace_raw_flags & value == value


def hasFlag(value: int, right: ADRights) -> bool:
    return value & right == right


def has_extended_right(ace: dict, binrightguid: str) -> bool:
    if not hasFlag(ace.get("Raw Access Required"), ADRights.get("ExtendedRight")):
        return False
    if not ace.get("Object Flags").get("Object Type Present"):
        return True
    if ace.get("GUID").strip("{}") == binrightguid:
        return True
    return False


def ace_applies(ace_guid: str, object_type: str, guid_map: dict) -> bool:
    if ace_guid.strip("{}") == guid_map[object_type]:
        return True
    return False


def can_write_property(ace: dict, binproperty: str) -> bool:
    if not hasFlag(ace.get("Raw Access Required"), ADRights.get("WriteProperty")):
        return False
    if not ace.get("Object Flags").get("Object Type Present"):
        return True
    if ace.get("GUID").strip("{}") == binproperty:
        return True
    return False


def is_dacl_protected(mask: int) -> bool:
    return bin(mask)[2:][3] == "1"


def parse_gmsa(data: dict, object_map: dict) -> list:
    results = []
    if "msDS-GroupMSAMembership" in data.keys():
        # Find principals who can read the password
        readers_sd = parse_ntSecurityDescriptor(data.get("msDS-GroupMSAMembership"))
        for ace in readers_sd["DACL"]["ACEs"]:
            reader_sid = ace["SID"]
            reader_object_type = object_map[reader_sid]["type"]
            results.append(
                {
                    "PrincipalSID": reader_sid,
                    "PrincipalType": reader_object_type,
                    "RightName": "ReadGMSAPassword",
                    "IsInherited": False,
                }
            )
    return results


def processAces(
    aces: list,
    entry: dict,
    object_type: ObjectType,
    domain: str,
    object_map: dict,
    guid_map: dict,
) -> list:
    # aces: list of raw ACEs to parse for the current entry
    # entry: object being processed
    # object_type: object type of the principal that has ACE on the entry
    # domain: domain of the object
    # object_map:
    # guid_map: guid-object mapping

    results = []
    # Parse owner
    owner_sid = aces.get("Owner SID")

    ignoresids = ["S-1-3-0", "S-1-5-18", "S-1-5-10"]
    if owner_sid not in ignoresids:
        owner_sidtype = object_map[owner_sid]["type"]
        r = {
            "PrincipalSID": (
                owner_sid
                if owner_sid.startswith("S-1-5-21-")
                else "%s-%s" % (domain.upper(), owner_sid)
            ),
            "PrincipalType": owner_sidtype.capitalize(),
            "RightName": EdgeNames.Owns.name,
            "IsInherited": False,
        }
        results.append(r)

    aces = aces.get("DACL").get("ACEs")
    for ace in aces:
        acerawtype = ace.get("Raw Type")
        if acerawtype != 5 and acerawtype != 0:
            continue
        sid = ace.get("SID")
        if sid[sid.find("S-1-") :] in ignoresids:
            continue
        rightname = ""
        acetype = ace.get("Type")
        sidtype = ""
        if sid in WELLKNOWN_SIDS:
            _, sidtype = WELLKNOWN_SIDS[sid]
            sid = "%s-%s" % (domain.upper(), sid)
        else:
            try:
                sidtype = object_map[sid]["type"]
            except:
                # principal is not found
                # might be a deleted object
                sidtype = "base"

        r = {
            "PrincipalSID": sid,
            "PrincipalType": sidtype.capitalize(),
            "RightName": rightname,
            "IsInherited": False,
        }

        if acerawtype == 0:
            # permissions applies broadly
            is_inherited = ace_has_Flags(ACE.INHERITED_ACE.value, ace.get("Raw Flags"))
            mask = ace.get("Raw Access Required")

            if hasFlag(mask, ADRights.get("GenericAll")):
                r2 = r.copy()
                r2["RightName"] = EdgeNames.GenericAll.name
                r2["IsInherited"] = is_inherited
                results.append(r2)
                continue

            if hasFlag(mask, ADRights.get("GenericWrite")):
                if object_type.value in ["user", "group", "computer", "gpo"]:
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.GenericWrite.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)

            if hasFlag(mask, ADRights.get("WriteOwner")):
                r2 = r.copy()
                r2["RightName"] = EdgeNames.WriteOwner.name
                r2["IsInherited"] = is_inherited
                results.append(r2)

            if object_type.value in ["user", "domain"] and hasFlag(
                mask, ADRights.get("ExtendedRight")
            ):
                # FIXME
                # if (
                #    entry["ObjectIdentifier"]
                #    == "S-1-5-21-361363594-1987475875-3919384990-1231"
                # ):
                #    if sid == "S-1-5-21-361363594-1987475875-3919384990-512":
                #        breakpoint()
                r2 = r.copy()
                r2["RightName"] = EdgeNames.AllExtendedRights.name
                r2["IsInherited"] = is_inherited
                results.append(r2)

            if (
                object_type.value == "computer"
                and hasFlag(mask, ADRights.get("ExtendedRight"))
                and not sid.endswith("S-1-5-32-544")
                and not sid.endswith("-512")
            ):
                r2 = r.copy()
                r2["RightName"] = EdgeNames.AllExtendedRights.name
                r2["IsInherited"] = is_inherited
                results.append(r2)

            if hasFlag(mask, ADRights.get("WriteDacl")):
                r2 = r.copy()
                r2["RightName"] = EdgeNames.WriteDacl.name
                r2["IsInherited"] = is_inherited
                results.append(r2)

            if (
                hasFlag(mask, ADRights.get("Self"))
                and not sid.endswith("S-1-5-32-544")
                and not sid.endswith("-512")
                and not sid.endswith("-519")
            ):
                if object_type.value == "group":
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.AddSelf.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)

        if acerawtype == 5:
            # ACCESS_ALLOWED_OBJECT_ACE
            # more detailed permissions control
            is_inherited = ace_has_Flags(ACE.INHERITED_ACE.value, ace.get("Raw Flags"))
            if not is_inherited and ace_has_Flags(
                ACE.INHERIT_ONLY_ACE.value, ace.get("Raw Flags")
            ):
                # ACE is set on this object, but only inherited, so not applicable to us
                continue

            # Check if the ACE has restrictions on object type (inherited case)
            if is_inherited and ace.get("Object Flags").get(
                "Inherited Object Type Present"
            ):
                # Verify if the ACE applies to this object type
                if not ace_applies(
                    ace.get("Inherited GUID").lower(), object_type.value, guid_map
                ):
                    continue

            mask = ace.get("Raw Access Required")

            # Check generic access masks first
            if (
                hasFlag(mask, ADRights.get("GenericAll"))
                or hasFlag(mask, ADRights.get("WriteDacl"))
                or hasFlag(mask, ADRights.get("WriteOwner"))
                or hasFlag(mask, ADRights.get("GenericWrite"))
            ):
                if ace.get("Object Flags").get(
                    "Object Type Present"
                ) and not ace_applies(
                    ace.get("GUID").lower(), object_type.value, guid_map
                ):
                    continue
                if hasFlag(mask, ADRights.get("GenericAll")):
                    if (
                        object_type.value == "computer"
                        and ace.get("Object Flags").get("Object Type Present")
                        and entry.get("Properties").get("haslaps")
                    ):
                        if ace.get("GUID").lower() == guid_map["ms-mcs-admpwd"]:
                            r2 = r.copy()
                            r2["RightName"] = EdgeNames.ReadLAPSPassword.name
                            r2["IsInherited"] = is_inherited
                            results.append(r2)
                    else:
                        r2 = r.copy()
                        r2["RightName"] = EdgeNames.GenericAll.name
                        r2["IsInherited"] = is_inherited
                        results.append(r2)
                    continue

                if hasFlag(mask, ADRights.get("GenericWrite")):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.GenericWrite.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)
                    if (
                        object_type.value != "domain"
                        and object_type.value != "computer"
                    ):
                        continue

                if hasFlag(mask, ADRights.get("WriteDacl")):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.WriteDacl.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)

                if hasFlag(mask, ADRights.get("WriteOwner")):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.WriteOwner.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)

            # Property write privileges
            if hasFlag(mask, ADRights.get("WriteProperty")):
                if object_type.value in [
                    "user",
                    "group",
                    "computer",
                    "gpo",
                ] and not ace.get("Object Flags").get("Object Type Present"):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.GenericWrite.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)
                if object_type.value == "group" and can_write_property(
                    ace, ACEGuids.WriteMember.value
                ):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.AddMember.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)
                if object_type.value == "computer" and can_write_property(
                    ace, ACEGuids.WriteAllowedToAct.value
                ):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.AddAllowedToAct.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)
                if object_type.value == "computer" and can_write_property(
                    ace, ACEGuids.UserAccountRestrictions.value
                ):  # and not sid.endswith("-512"):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.WriteAccountRestrictions.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)
                if object_type.value == "organizational-unit" and can_write_property(
                    ace, ACEGuids.WriteGPLink.value
                ):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.WriteGPLink.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)

                # Key credential link
                if (
                    object_type.value in ["user", "computer"]
                    and ace.get("Object Flags").get("Object Type Present")
                    and "ms-ds-key-credential-link" in guid_map
                    and ace.get("GUID").lower().strip("{}")
                    == guid_map["ms-ds-key-credential-link"]
                ):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.AddKeyCredentialLink.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)

                # ServicePrincipalName property write rights
                if (
                    object_type.value == "user"
                    and ace.get("Object Flags").get("Object Type Present")
                    and ace.get("GUID").lower() == guid_map["service-principal-name"]
                ):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.WriteSPN.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)

            elif hasFlag(mask, ADRights.get("Self")):
                if (
                    object_type.value == "group"
                    and sidtype == ACEGuids.WriteMember.value
                ):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.AddSelf.name
                    results.append(r2)

            # Property read privileges
            if hasFlag(mask, ADRights.get("ReadProperty")):
                if (
                    object_type.value == "computer"
                    and ace.get("Object Flags").get("Object Type Present")
                    and entry.get("Properties").get("haslaps")
                ):
                    if ace.get("GUID").lower() == guid_map["ms-mcs-admpwd"]:
                        r2 = r.copy()
                        r2["RightName"] = EdgeNames.ReadLAPSPassword.name
                        r2["IsInherited"] = is_inherited
                        results.append(r2)

            # Extended rights
            if hasFlag(mask, ADRights.get("ExtendedRight")):
                if object_type.value in ["user", "domain"] and not ace.get(
                    "Object Flags"
                ).get("Object Type Present"):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.AllExtendedRights.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)
                if object_type.value == "computer" and not ace.get("Object Flags").get(
                    "Object Type Present"
                ):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.AllExtendedRights.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)
                if object_type.value == "domain" and has_extended_right(
                    ace, ACEGuids.DSReplicationGetChanges.value
                ):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.GetChanges.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)
                if object_type.value == "domain" and has_extended_right(
                    ace, ACEGuids.DSReplicationGetChangesAll.value
                ):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.GetChangesAll.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)
                if object_type.value == "domain" and has_extended_right(
                    ace, ACEGuids.DSReplicationGetChangesInFilteredSet.value
                ):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.GetChangesInFilteredSet.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)
                if object_type.value == "user" and has_extended_right(
                    ace, ACEGuids.UserForceChangePassword.value
                ):
                    r2 = r.copy()
                    r2["RightName"] = EdgeNames.ForceChangePassword.name
                    r2["IsInherited"] = is_inherited
                    results.append(r2)

    return results
