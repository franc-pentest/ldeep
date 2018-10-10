
from sys import __stdout__, __stderr__, exit
from termcolor import colored


def info(content):
	__stderr__.write("%s\n" % colored("[+] " + content, "blue", attrs=["bold"]))


def error(content):
	__stderr__.write("%s\n" % colored("[!] " + content, "red", attrs=["bold"]))
	exit(1)


class Logger(object):

	def __init__(self, outfile=None, quiet=False):
		self.quiet = quiet
		self.terminal = __stdout__
		self.log = open(outfile, 'w') if outfile else None

	def write(self, message):
		if not self.quiet:
			self.terminal.write(message)
		if self.log:
			self.log.write(message)

	def flush(self):
		if self.log:
			self.log.flush()
		pass

