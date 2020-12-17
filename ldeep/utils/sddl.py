#!/usr/bin/env python3

"""
A module used to handle binary ntSecurityDescriptor from Active Directory LDAP.
"""

from struct import unpack

from ldap3.protocol.formatters.formatters import format_sid, format_uuid

SDDLTypeFlags = {
	'Self Relative'					: 0b1000000000000000,
	'RM Control Valid'				: 0b0100000000000000,
	'SACL Protected'				: 0b0010000000000000,
	'DACL Protected'				: 0b0001000000000000,
	'SACL Auto Inherit'				: 0b0000100000000000,
	'DACL Auto Inherit'				: 0b0000010000000000,
	'SACL Auto Inherit Required'	: 0b0000001000000000,
	'DACL Auto Inherit Required'	: 0b0000000100000000,
	'Server Security'				: 0b0000000010000000,
	'DACL Trusted'					: 0b0000000001000000,
	'SACL Defaulted'				: 0b0000000000100000,
	'SACL Present'					: 0b0000000000010000,
	'DACL Defaulted'				: 0b0000000000001000,
	'DACL Present'					: 0b0000000000000100,
	'Group Defaulted'				: 0b0000000000000010,
	'Owner Defaulted'				: 0b0000000000000001,
}

SID_SIZE = 28


def parse_ntSecurityDescriptor(input_buffer):
	""" Parses a ntSecurityDescriptor.
	"""
	out = dict()

	fields = ('Revision', 'Raw Type', 'Offset to owner SID', 'Offset to group SID', 'Offset to SACL', 'Offset to DACL')

	for k, v in zip(fields, unpack('<HHIIII', input_buffer[:20])):
		out[k] = v

	out['Type'] = parse_sddl_type(out['Raw Type'])

	for x in ('Owner', 'Group'):
		offset = out['Offset to %s SID' % (x.lower())]
		out['%s SID' % x] = format_sid(input_buffer[offset:offset + SID_SIZE])

	if out['Type']['SACL Present']:
		out['SACL'] = parse_acl(input_buffer[out['Offset to SACL']:])

	if out['Type']['DACL Present']:
		out['DACL'] = parse_acl(input_buffer[out['Offset to DACL']:])

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
	fields = ('Revision', 'Size', 'Num ACEs')

	for k, v in zip(fields, unpack('<HHI', input_buffer[:8])):
		out[k] = v

	out['ACEs'] = parse_aces(input_buffer[8:8 + out['Size']], out['Num ACEs'])
	return out


def parse_aces(input_buffer, count):
	"""
	Parses the list of ACEs.
	"""
	out = []
	while len(out) < count:
		ace = dict()
		fields = ('Raw Type', 'Raw Flags', 'Size', 'Raw Access Required')
		for k, v in zip(fields, unpack('<BBHI', input_buffer[:8])):
			ace[k] = v

		ace['Type'] = parse_sddl_dacl_ace_type(ace['Raw Type'])

		ace['Access Required'] = parse_ace_access(ace['Raw Access Required'])

		offset = 8

		if ace['Type'].endswith('Object'):
			fields = ('Raw Object Flags', )
			for k, v in zip(fields, unpack('<I', input_buffer[8:12])):
				ace[k] = v
			ace['Object Flags'] = parse_ace_object_flags(ace['Raw Object Flags'])

			offset = 12
			if ace['Object Flags']['Object Type Present']:
				ace['GUID'] = format_uuid(input_buffer[offset:offset + 16])
				offset += 16
			if ace['Object Flags']['Inherited Object Type Present']:
				ace['Inherited GUID'] = format_uuid(input_buffer[offset:offset + 16])
				offset += 16

			ace['SID'] = format_sid(input_buffer[offset:ace['Size']])

		ace['SID'] = format_sid(input_buffer[offset:ace['Size']])

		input_buffer = input_buffer[ace['Size']:]

		out.append(ace)
	return out


ACEAccessFlags = {
	'Generic Read'			: 0b10000000000000000000000000000000,
	'Generic Write'			: 0b01000000000000000000000000000000,
	'Generic Execute'		: 0b00100000000000000000000000000000,
	'Generic All'			: 0b00010000000000000000000000000000,
	'Maximum Allowed'		: 0b00000010000000000000000000000000,
	'Access SACL'			: 0b00000000100000000000000000000000,
	'Synchronise'			: 0b00000000000100000000000000000000,
	'Write Owner'			: 0b00000000000010000000000000000000,
	'Write DAC'				: 0b00000000000001000000000000000000,
	'Read Control'			: 0b00000000000000100000000000000000,
	'Delete'				: 0b00000000000000010000000000000000,
	'Ads Control Access'	: 0b00000000000000000000000100000000,
	'Ads List Object'		: 0b00000000000000000000000010000000,
	'Ads Delete Tree'		: 0b00000000000000000000000001000000,
	'Ads Write Prop'		: 0b00000000000000000000000000100000,
	'Ads Read Prop'			: 0b00000000000000000000000000010000,
	'Ads Self Write'		: 0b00000000000000000000000000001000,
	'Ads List'				: 0b00000000000000000000000000000100,
	'Ads Delete Child'		: 0b00000000000000000000000000000010,
	'Ads Create Child'		: 0b00000000000000000000000000000001
}


def parse_ace_access(input_buffer):
	"""
	Parses access flags in an ACE.
	"""
	return resolve_flags(input_buffer, ACEAccessFlags)


ACEObjectFlags = {
	'Object Type Present'				: 0b00000000000000000000000000000010,
	'Inherited Object Type Present'		: 0b00000000000000000000000000000001
}


def parse_ace_object_flags(input_buffer):
	"""
	Parses flags in an ACE containing an object.
	"""
	return resolve_flags(input_buffer, ACEObjectFlags)


ACEType = {
	0x00: 'Access Allowed',
	0x01: 'Access Denied',
	0x02: 'System Audit',
	0x03: 'System Alarm',
	0x04: 'Access Allowed Compound',
	0x05: 'Access Allowed Object',
	0x06: 'Access Denied Object',
	0x07: 'System Audit Object',
	0x08: 'System Alarm Object',
	0x09: 'Access Allowed Callback',
	0x0A: 'Access Denied Callback',
	0x0B: 'Access Allowed Callback Object',
	0x0C: 'Access Denied Callback Object',
	0x0D: 'System Audit Callback',
	0x0E: 'System Alarm Callback',
	0x0F: 'System Audit Callback Object',
	0x10: 'System Alarm Callback Object',
	0x11: 'System Mandatory Label',
	0x12: 'System Resource Attribute',
	0x13: 'System Scoped Policy ID'
}


def parse_sddl_dacl_ace_type(ace_type):
	"""
	Parses the type of an ACE.
	"""
	return ACEType[ace_type]
