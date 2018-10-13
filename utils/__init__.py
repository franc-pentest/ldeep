
from sys import __stdout__, __stderr__, exit
from termcolor import colored
from multiprocessing.dummy import Pool as ThreadPool
from tqdm import tqdm

import dns.resolver


def info(content):
	__stderr__.write("%s\n" % colored("[+] " + str(content), "blue", attrs=["bold"]))


def error(content):
	__stderr__.write("%s\n" % colored("[!] " + str(content), "red", attrs=["bold"]))
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


class ResolverThread(object):

	def __init__(self, dns_server):
		self.dns_server = dns_server
		self.resolutions = []

	def resolve(self, hostname):
		if self.dns_server:
			resolver = dns.resolver.Resolver()
			resolver.nameservers = [self.dns_server]
		else:
			resolver = dns.resolver
		try:
			answers = resolver.query(hostname, 'A', tcp=True)
			for rdata in answers:
				if rdata.address:
					self.resolutions.append({
						"hostname": hostname,
						"address": rdata.address
					})
					break
			else:
				pass
		except Exception:
			pass


def resolve(hostnames, dns_server):
	pool = ThreadPool(20)
	resolver_thread = ResolverThread(dns_server)
	with tqdm(total=len(hostnames)) as pbar:
		for _ in pool.imap_unordered(resolver_thread.resolve, tqdm(hostnames, desc="Resolution", bar_format="{desc} {n_fmt}/{total_fmt} hostnames")):
			pbar.update()
	pool.close()
	pool.join()
	results_set = []
	for computer in resolver_thread.resolutions:
		results_set.append(computer)
	return results_set
