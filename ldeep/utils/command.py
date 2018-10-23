
from ast import literal_eval
from inspect import getmembers
from re import findall


class Command():

	@staticmethod
	def __parse_docstring(docstring):
		"""
		Parse a docstring to extract help and argument to generate a subparsers with arguments.
		The expected format is (triple quotes are replaced by { and }):

			{{{
			Help line

			Arguments:
				@argumentName:argumentType
				@argumentName:argumentType = value
				#argumentName:argumentType
				#argumentName:argumentType = value
			}}}

		@ means an optional argument that is not required.
		# means a positional argument (should have a value if it's a not required option).
		"""
		result = {}
		lines = docstring.replace("\t", "").split("\n")
		help_line = ""
		arguments = {}

		s_argument = False
		while lines != []:
			line = lines.pop(0).strip()

			if line.strip() == "":
				continue

			else:
				if not s_argument:
					if line == "Arguments:":
						s_argument = True
					else:
						help_line += " " + line
				else:
					if line[0] in ["@", "#"]:
						opt = line[0]
						arg = line[1:]
						variable, _, values = arg.partition(" = ")
						name, _, typ = variable.partition(':')

						alias = name[0]
						arguments[name] = {
							"alias": "-{alias}".format(alias=alias),
							"name": "--{name}".format(name=name),
							"type": typ,
							"help_line": "",
						}
						if values and typ in ["list"]:
							arguments[name]["values"] = literal_eval(values)
						elif values and typ == "string":
							arguments[name]["value"] = values

						if opt == "#":
							arguments[name]["pos"] = True
						elif opt == "@":
							arguments[name]["pos"] = False

					elif line:  # if no prefix is found, read the help line of the previous argument.
						if not arguments[name]["help_line"]:
							arguments[name]["help_line"] = line
						else:
							arguments[name]["help_line"] += " " + line

		return {"help_line": help_line.strip(), "arguments": arguments}

	@classmethod
	def get_commands(cls, prefix=""):
		"""
		Iterator yielding object methods with

		:prefix: filter object methods to return
		"""
		for method, func in getmembers(cls):
			if method.startswith(prefix) and method != "get_commands":
				command = findall("{}_?(.*)".format(prefix), method)[0]
				yield (command, method)

	@classmethod
	def set_subparser_for(cls, command, method, subparser):
		"""
		Take a subparser as argument and add arguments corresponding to command in it.

		:command: name to display in the help
		:method: function name corresponding to the command
		:subparser: subparser object to add argument(s) to
		"""
		func = getattr(cls, method)
		args_info = cls.__parse_docstring(func.__doc__)
		c = subparser.add_parser(command, help=args_info["help_line"])

		if "arguments" in args_info:
			for label, arg in args_info["arguments"].items():
				if arg["pos"]:
					if arg["type"] in ["string", "int"] and "value" in arg:
						c.add_argument(label, nargs='?', default=arg["value"], help=arg["help_line"])
					else:
						c.add_argument(label, help=arg["help_line"])
				else:
					if arg["type"] == "bool":
						c.add_argument(arg["alias"], arg["name"], action="store_true", default=False, help=arg["help_line"])
					elif arg["type"] in ["string", "int"] and "value" in arg:
						c.add_argument(label, default=arg["value"][0], nargs="?", help=arg["help_line"])
					elif arg["type"] == "string":
						c.add_argument(arg["alias"], arg["name"], default="", help=arg["help_line"])
					elif arg["type"] == "list" and "values" in arg:
						c.add_argument(label, choices=arg["values"], default=arg["values"][0], nargs="?", help=arg["help_line"])

	def has_option(self, method, option):
		return option in getattr(self, method).__doc__
