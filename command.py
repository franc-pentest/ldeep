
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
			}}}
		"""
		result = {}
		lines = docstring.replace("\t", "").split("\n")
		result["help_line"] = lines[1]
		if len(lines) > 3:  # third line should be empty
			if lines[3] == "Arguments:":
				result["arguments"] = dict()
				for arg in lines[4:]:
					if arg.startswith('@'):
						arg = arg[1:]
						variable, _, values = arg.partition(' = ')
						name, _, typ = variable.partition(':')
						alias = name[0]
						arg_dict = {
							"alias": "-{alias}".format(alias=alias),
							"name": "--{name}".format(name=name),
							"type": typ
						}
						if values and typ in ["list"]:
							arg_dict["values"] = literal_eval(values.strip())
						result["arguments"][name] = arg_dict
					elif arg:  # if no prefix is found, read the help line of the previous argument.
						result["arguments"][name]["help_line"] = arg
		return result

	@classmethod
	def get_commands(cls, prefix=""):
		"""
		Iterator yielding object methods with

		@prefix: filter object methods to return
		"""
		for method, func in getmembers(cls):
			if method.startswith(prefix):
				command = findall("{}_?(.*)".format(prefix), method)[0]
				yield (command, method)

	@classmethod
	def set_subparser_for(cls, command, method, subparser):
		func = getattr(cls, method)
		args_info = cls.__parse_docstring(func.__doc__)
		c = subparser.add_parser(command, help=args_info["help_line"])

		if "arguments" in args_info:
			for label, dic in args_info["arguments"].items():
				if dic["type"] == "bool":
					c.add_argument(dic["alias"], dic["name"], action="store_true", default=False, help=dic["help_line"])
				elif dic["type"] == "string":
					c.add_argument(dic["alias"], dic["name"], default="", help=dic["help_line"])
				elif dic["type"] == "list" and dic["values"]:
					c.add_argument(label, choices=dic["values"], default=dic["values"][0], nargs="?")
