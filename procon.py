#!/usr/bin/env python3

import os, pwd, time, sys, string
from optparse import OptionParser

IPv4_LOCALHOST = '0100007F'
IPv4_ALLHOST = '00000000'

TCP_STATE_LISTEN = '0A'
TCP_STATE_ESTABLISHED = '01'

MAX_CMDLINE_LENGTH = 80

NOW_EPOCH = time.time()


# include/net/tcp_states.h
# TCP_ESTABLISHED = 1,	01
# TCP_SYN_SENT,			02
# TCP_SYN_RECV,			03
# TCP_FIN_WAIT1,		04
# TCP_FIN_WAIT2,		05
# TCP_TIME_WAIT,		06
# TCP_CLOSE,			07
# TCP_CLOSE_WAIT,		08
# TCP_LAST_ACK,			09
# TCP_LISTEN,			0A
# TCP_CLOSING,			0B

parser = OptionParser()
parser.add_option('-v', action='store_true', dest='verbose', default=False, help = 'verbose')
parser.add_option('-g', action='store_true', dest='generate', default=False, help = 'generate allow lines')
parser.add_option('-a', action='append', type=str, dest='allow_files', default=[], help = 'allow rconf file with process whitelisting (can be repeated)')
parser.add_option('-b', action='store', type=int, dest='bin_age', default=[], help = 'min age of running binaries (hours)')
(opts, args) = parser.parse_args(sys.argv[1:])


def assert_power():
	"""Summary: exit if not root
	"""
	if os.getuid() != 0:
		print('Must run as root!')
		sys.exit(1)


def get_pids():
	"""Summary: return running pids, or pids that were explicitly specified by the user.
	
	Returns:
	    list:	list of pids (strings looking like ints)
	"""
	my_pid = str(os.getpid())
	my_ppid = str(os.getppid())
	#my_pppid = [line.split()[1] for line in open('/proc/'+my_ppid+'/status').readlines() if line.startswith('ppid:') ][0]

	me = [my_pid, my_ppid]
	#me = []	#todo rm

	# fetch all running process pids, as strings
	pids = [pid for pid in os.listdir('/proc') if pid.isdigit() and pid not in me]

	if args:
		pids = args

	return pids


def alert(severity, alert_string, variables):
	"""Summary: prints out alerts about stuff that may or may not cause exitvalue!=0
	
	Args:
	    severity (int):			0=warning 1=critical
	    alert_string (str):		Your message
	    variables (dict):		Optional, may be None. Tries to pretty print these. These are most likely process variables.
	
	Returns:
	    None
	"""
	if severity == 0:
		SEV = 'WARNING'
	elif severity == 1:
		SEV = 'CRITICAL'
	else:
		SEV = 'WHAT'

	if variables:
		try:
			print('%s(%s) uid:%s user:%s pid:%s exe:%s comm:%s cmdline:%s runtime:%.2fh exeage:%.2fh' % (SEV, alert_string, variables['uid'], variables['user'], variables['pid'], variables['exe'], variables['comm'], variables['cmdline'], variables['runtime'], variables['exeage']))
		except:
			print('%s(%s) %s' % (SEV, alert_string, variables))
	else:
		print('%s! %s' % (SEV, alert_string))


def print_verbose(msg, *rest):
	"""Summary: print message to user only when -v is used
	
	Args:
	    msg (str):	message
	    *rest:		optional rest, like e.g. a dict, or array or whatever
	"""
	if opts.verbose:
		if not msg:
			print()
		elif rest:
			print('VERBOSE:', msg, rest)
		else:
			print('VERBOSE:', msg)


def parse_procs_conf(allow_files):
	"""Summary
	
	Args:
	    allow_files (list): list of cfg files
	
	Returns:
	    list: list of whitelisting lines, looking like this [VARS, VALS, EXTRAS_DICT, where, line, hits(0)]
	
	Raises:
	    e: Description
	    Exception: Description
	"""
	tmp_var_vals = []

	# read conf from conf files
	# save a tuple for each row, containing (file:row, line)
	# purging of comments happen here
	proc_whitelist_lines = []
	for f in allow_files:
		i = 0
		for line in open(f).readlines():
			i += 1
			line = line.rstrip()
			j = line.find('#')
			if j >= 0:
				line = line[:j]
			line = line.rstrip()
			if not line or line.startswith('#'):
				continue
			proc_whitelist_lines.append(('%s:%i' % (f, i), line))

	# parse conf into whitelisting array
	PROC_WHITELIST_LINES_EXPLODED = []
	for where, line in proc_whitelist_lines:
		tmp = [col for col in line.split() if col]
		VARS = tmp[0].lower().split('_')
		nr_vars = len(VARS)
		VALS = tmp[1:nr_vars+1]

		if len(VALS) != nr_vars:
			raise Exception('nr-vars != nr-vals in %s: %s' % (where, line))

		if (VARS, VALS) in tmp_var_vals:
			raise Exception('line duplicate %s: %s' % (where, line))

		EXTRAS_DICT = {}
		EXTRAS = tmp[nr_vars+1:]
		for extra in EXTRAS:
			try:
				var, val = extra.split('=')
			except Exception as e:
				raise Exception('error parsing extra values at %s: %s' % (where, line))

			if var in list(EXTRAS_DICT.keys()):
				EXTRAS_DICT[var].append(val.split(':'))
			else:
				EXTRAS_DICT[var] = [val.split(':')]
		PROC_WHITELIST_LINES_EXPLODED.append([VARS, VALS, EXTRAS_DICT, where, line, 0])
		tmp_var_vals.append((VARS, VALS))

	return PROC_WHITELIST_LINES_EXPLODED


def hexip4_to_ip4(hex_ip):
	"""Summary: make printable the ip stuff in /proc/net/tcp etc
	
	Args:
	    hex_ip (str): an ip string like this 0100007F
	
	Returns:
	    str: a dotted decimal ip string like this 127.0.0.1
	"""
	r = str(int(hex_ip[6:8], 16))
	r += '.' + str(int(hex_ip[4:6], 16))
	r += '.' + str(int(hex_ip[2:4], 16))
	r += '.' + str(int(hex_ip[0:2], 16))
	return r


def get_proc_net_maps():
	"""Summary: return a dict of dicts, containing info about global network connections
	
	Returns:
	    dict of dicts: Like {'tcp4': {'100721': [con, parts, ...]}, 'udp4': {...} }
	"""
	r = {}

	proc_net_tcp4 = [ line.split() for line in open('/proc/net/tcp').readlines() if line.strip()[:2] != 'sl']
	proc_net_tcp4_map = {}
	# create a map with the inode as key
	for parts in proc_net_tcp4:
		proc_net_tcp4_map[parts[9]] = parts
	r['tcp4'] = proc_net_tcp4_map

	proc_net_udp4 = [ line.split() for line in open('/proc/net/udp').readlines() if line.strip()[:2] != 'sl']
	proc_net_udp4_map = {}
	# create a map with the inode as key
	for parts in proc_net_udp4:
		proc_net_udp4_map[parts[9]] = parts
	r['udp4'] = proc_net_udp4_map

	return r


def get_all_listening_nonlocalhost_ip4_ports(proc_net_map):
	"""Summary: get list of all listening hosts, that listen publicly (non-localhost)
	
	Args:
	    proc_net_map (dict): Description
	
	Returns:
	    list: like ['22', '443', ...]
	"""
	return [ str(int(parts[1][9:], 16)) for inode, parts in list(proc_net_map.items()) if parts[3] == TCP_STATE_LISTEN and parts[1][:8] != IPv4_LOCALHOST]


def main():
	assert_power()

	procs_invalid = []
	procs_approved = []
	procs_skipped = []
	procs_kernel  = []

	generated_allow_lines = []

	try:
		whitelisting_config = parse_procs_conf(opts.allow_files)
	except Exception as e:
		alert(1, 'Error parsing conf. %s' % (e), None)
		sys.exit(2)

	proc_net_maps = get_proc_net_maps()

	all_listening_nonlocalhost_tcp4_ports = get_all_listening_nonlocalhost_ip4_ports(proc_net_maps['tcp4'])
	all_listening_nonlocalhost_udp4_ports = get_all_listening_nonlocalhost_ip4_ports(proc_net_maps['udp4'])
	proc_net_maps['tcp4']['all_listening_nonlocalhost_ports'] = all_listening_nonlocalhost_tcp4_ports
	proc_net_maps['udp4']['all_listening_nonlocalhost_ports'] = all_listening_nonlocalhost_udp4_ports

	pids = get_pids()

	for pid in pids:
		print()
		print('checking pid', pid)

		v = get_process_variables(pid)
		if not v:
			procs_skipped.append(pid)
			continue

		ofs = get_process_open_files(pid, proc_net_maps)
		print(v['comm'])

		if proc_is_kernel(v):
			print('pid is kernel', pid)
			procs_kernel.append(pid)
			continue

		procs_approved.append(pid)

		if not check_process_ok(pid, v, ofs, whitelisting_config, proc_net_maps):
			print(pid, 'nok')
			procs_invalid.append(pid)

			if opts.generate:
				generated_allow_lines.append( generate(pid, v, ofs, proc_net_maps) )
		else:
			print(pid, 'ok')

	print()
	print('approved', procs_approved)
	print('skipped', procs_skipped)
	print('invalid', procs_invalid)
	print('kernel', procs_kernel)

	if opts.generate:
		print('****************************** GENERATED ******************************')
		for gal in generated_allow_lines:
			print(gal)

	if procs_invalid:
		sys.exit(11)
	else:
		sys.exit(0)


def generate(pid, variables, open_files, proc_net_maps):
	if int(variables['uid']) < 1000:
		allow_variables = ['user', 'exe', 'comm', 'cmdline']
	else:
		allow_variables = ['uid', 'exe', 'comm', 'cmdline']

	# allow variable values
	avv = [ variables[av] for av in allow_variables ]

	if allow_variables[0] == 'uid':
		avv[0] = '>999'

	allow_line = '_'.join( [ i.upper() for i in allow_variables ] )
	allow_line += '\t' + '\t'.join(avv)

	all_listening_nonlocalhost_tcp4_ports = proc_net_maps['tcp4']['all_listening_nonlocalhost_ports']

	for file_type in list(open_files.keys()):
		if file_type == 'regular':
			for file in open_files['regular']:
				if file.startswith('/etc'):
					allow_line += '\tFS_FILE_OK=%s' % (file)
		else:
			for file in open_files[file_type]:
				if file['state'] == TCP_STATE_LISTEN:
					if file['local_ip4'] == IPv4_ALLHOST:
						ip = '*'
					else:
						ip = hexip4_to_ip4(file['local_ip4'])
					allow_line += '\tNET_LISTEN=%s:%s' % (ip, file['local_port'])

				elif file['state'] == TCP_STATE_ESTABLISHED:
					if file['local_port'] in all_listening_nonlocalhost_tcp4_ports:
						#incoming connection
						pass
					else:
						allow_line += '\tNET_CON_OUT=%s:%s' % (hexip4_to_ip4(file['remote_ip4']), file['remote_port'])

	return allow_line

def get_process_variables(pid):
	pid_dir = os.path.join('/proc', pid) + os.sep
	exe = None

	try:
		uid = str(os.stat(pid_dir).st_uid)
	except FileNotFoundError:
		return None

	# procs exe file
	exeage = 0.0
	try:
		exe = os.readlink(pid_dir + 'exe')
		if ' (deleted)' in exe:
			exeage = (NOW_EPOCH - os.stat(exe[:-10]).st_mtime) / 3600.0
			alert(1, 'deleted file running', proc_variables())
			exe = exe[:-10]
		else:
			# executable files age (since last modified)
			exeage = (NOW_EPOCH - os.stat(exe).st_mtime) / 3600.0
	except OSError:
		exe = None
		exeage = 0

		if uid == '0':
			#kernel process
			pass
		else:
			alert(1, 'proc with no exe and not running as root', locals())

	# procs user name
	try:
		user = pwd.getpwuid(int(uid)).pw_name
	except KeyError:
		user = None
		alert(1, 'no matching username for uid%s (pid=%s)' % (uid, pid), locals())

	for line in open('/proc/%s/status' % (pid)).readlines():
		line = line.strip().replace('\t', ' ')
		if line:
			if line.startswith('Name:'):
				status_name = line.split(' ', 1)[1]
			elif line.startswith('State:'):
				status_state = line.split(' ', 1)[1][0]
			elif line.startswith('Threads:'):
				status_threads = line.split(' ', 1)[1]
	del line


	if status_state.startswith('Z'):
		alert(2, 'zombie process', locals())

	# procs command line
	cmdline = open(pid_dir + 'cmdline').read()
	if cmdline:
		cmdline = cmdline.replace(chr(0), ' ')
		cmdline = cmdline.strip()
		cmdline_parts = cmdline.split()
		i = cmdline_parts[0].rfind('/')
		if i >= 0:
			cmdline_parts[0] = cmdline_parts[0][i+1:]
			cmdline_short = ' '.join(cmdline_parts)
		else:
			cmdline_short = cmdline

		cmdline = cmdline.replace(' ', '^')
		cmdline = cmdline[:MAX_CMDLINE_LENGTH]
		cmdline_short = cmdline_short.replace(' ', '^')
		cmdline_short = cmdline_short[:MAX_CMDLINE_LENGTH]

		del cmdline_parts, i

	runtime = (NOW_EPOCH - os.stat(pid_dir + 'cmdline').st_mtime) / 3600.0

	# procs command name
	comm = open(pid_dir + 'comm').read().strip()

	return locals()

def proc_is_kernel(v):
	return v['exe'] is None

def get_process_open_files(pid, proc_net_maps):
	'''Returns a dict of open files. Skips stuff like pipes, /dev/null and such.

	Args:
		pid (str):	the PID

	Returns:
		Dict of lists. Like e.g.
		...

		An IP socket contains [protocol, state, local_ip4, local_port, remote_ip4, remote_port]
		A regular file contains [filename]

	'''

	open_files = {'regular': [], 'tcp4': [], 'udp4': []}
	pid_fd_dir = os.path.join('/proc', pid, 'fd') + os.sep

	proc_net_tcp4_map = proc_net_maps['tcp4']
	proc_net_udp4_map = proc_net_maps['udp4']

	for ofd in os.listdir(pid_fd_dir):
		of = os.readlink(pid_fd_dir + ofd)

		if of.startswith(os.sep):
			if of.startswith('/dev/'):
				continue
			else:
				open_files['regular'].append(of)

		elif of.startswith('socket:'):
			inode = of.split('[')[1][:-1]

			if inode in list(proc_net_tcp4_map.keys()):
				sock = get_ip4_socket_from_inode(inode, proc_net_tcp4_map)
				open_files['tcp4'].append(sock)
			elif inode in list(proc_net_udp4_map.keys()):
				sock = get_ip4_socket_from_inode(inode, proc_net_udp4_map)
				open_files['udp4'].append(sock)
			else:
				continue

	return open_files

def get_ip4_socket_from_inode(inode, proc_net_map):
	parts = proc_net_map[inode]

	local = parts[1]
	remote = parts[2]
	state = parts[3]
	local_port = str(int(local[9:], 16))
	remote_port = str(int(remote[9:], 16))
	local_ip4 = local[:8]
	remote_ip4 = remote[:8]

	del parts, local, remote, proc_net_map
	return locals()


def check_process_ok(pid, proc_variables, open_files, whitelisting_config, proc_net_maps):
	proc_is_whitelisted = False

	for line_list in whitelisting_config:
		VARS, VALS, EXTRAS_DICT, where, line, hits = line_list

		proc_is_whitelisted = True
		for vr, vl in zip(VARS, VALS):
			
			if vr in ['exe', 'cmdline']:
				if vr == 'cmdline' and vl[0] not in ['.', '/']:
					vr = 'cmdline_short'
				if vl.endswith('>'):
					vl = vl[:-1]
					if not proc_variables[vr].startswith(vl):
						print('a')
						proc_is_whitelisted = False
						break
				else:
					if proc_variables[vr] != vl:
						print('b', vr, proc_variables[vr], vl)
						proc_is_whitelisted = False
						break
			elif vr == 'pid':
				if vl[0] == '<':
					if int(proc_variables[vr]) < int(vl[1:]):
						pass
					else:
						proc_is_whitelisted = False
						break
				elif vl[0] == '>':
					if int(proc_variables[vr]) > int(vl[1:]):
						pass
					else:
						proc_is_whitelisted = False
						break
				else:
					if int(vl) != int(pid):
						proc_is_whitelisted = False
						break
			elif vr == 'uid':
				if vl[0] == '<':
					if int(proc_variables[vr]) < int(vl[1:]):
						pass
					else:
						proc_is_whitelisted = False
						break
				elif vl[0] == '>':
					if int(proc_variables[vr]) > int(vl[1:]):
						pass
					else:
						proc_is_whitelisted = False
						break
				else:
					if int(vl) != int(proc_variables[vr]):
						proc_is_whitelisted = False
						break
			else:
				if proc_variables[vr] != vl:
					proc_is_whitelisted = False
					break

			vr = 'OPEN FILES'
			vl = None


		if proc_is_whitelisted:
			# it got whitelisted by the last cfg line, the variables at least
			break

	if proc_is_whitelisted:
		proc_is_whitelisted = check_process_open_files(pid, proc_variables, open_files, EXTRAS_DICT, where, proc_net_maps)

	return proc_is_whitelisted


def check_process_open_files(pid, proc_variables, open_files, EXTRAS_DICT, where, proc_net_maps):
	proc_is_whitelisted = True

	all_listening_nonlocalhost_tcp4_ports = proc_net_maps['tcp4']['all_listening_nonlocalhost_ports']
	all_listening_nonlocalhost_udp4_ports = proc_net_maps['udp4']['all_listening_nonlocalhost_ports']

	for file_type in list(open_files.keys()):
		if file_type == 'regular':
			for file in open_files['regular']:
				if file.startswith('/etc'):
					print('checking etc file', file)
				elif file.startswith('/usr') or file.startswith('/var') or file.startswith('/home'):
					pass
				else:
					print('checking rare file', file)
		else:
			if file_type == 'udp4':
				continue

			for file in open_files[file_type]:
				file_ok = False

				if file['local_ip4'] == IPv4_LOCALHOST:
					continue
				else:
					if file['state'] == TCP_STATE_LISTEN:
						if 'NET_LISTEN' in list(EXTRAS_DICT.keys()):
							for ip, port_range in EXTRAS_DICT['NET_LISTEN']:
								if ip != '*':
									if ip != file['local_ip4']:
										continue
								try:
									port_does_match_portrange(file['local_port'], port_range)
									print('ok file', file)
									file_ok = True
									break
								except ValueError as e:
									alert(-1, 'error in %s with port definition %s' % (where, port_range))
									sys.exit(42)

						if not file_ok:
							alert(1, 'process %s listens on non-localhost port %s' % (proc_variables['comm'], file['local_port']), proc_variables)

					else:
						if file['local_port'] in all_listening_nonlocalhost_tcp4_ports:
							if 'NET_CON_IN' in EXTRAS_DICT:
								pass
							else:
								alert(1, 'process %s has an inbound connection to local %s:%s from remote %s:%s in state %s' % (proc_variables['comm'], hexip4_to_ip4(file['local_ip4']), file['local_port'], hexip4_to_ip4(file['remote_ip4']), file['remote_port'], file['state']), proc_variables)
								print(file)
						else:
							if 'NET_CON_OUT' in EXTRAS_DICT:
								for ip, port in EXTRAS_DICT['NET_CON_OUT']:
									if port == file['remote_port']:
										file_ok = True
										break

							if not file_ok:
								if file['state'] == TCP_STATE_ESTABLISHED:
									alert(1, 'process %s has an active outbound connection to remote %s:%s' % (proc_variables['comm'], hexip4_to_ip4(file['remote_ip4']), file['remote_port']), proc_variables)
									print(file)
								else:
									alert(1, 'process %s has/had an outbound connection to remote %s:%s, now in state %s' % (proc_variables['comm'], hexip4_to_ip4(file['remote_ip4']), file['remote_port'], file['state']), proc_variables)
									print(file)

	return proc_is_whitelisted


def ip_does_match_iprange(ip, iprange):
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(iprange):
		return True
	else:
		return False


def port_does_match_portrange(port, portrange):
	port = int(port)
	print('check portrange %s' % (portrange))

	if '-' in portrange:
		x, y = portrange.split('-')
		x = int(x)
		y = int(y)

		assert x > 0 and x < 65536, 'port value %i outside range 1-65535' % (x)
		assert y > 0 and y < 65536, 'port value %i outside range 1-65535' % (y)
		assert not (x > y), 'port %i cant be larger than port %i' % (x, y)

	else:
		if port == int(portrange):
			return True
		else:
			return False

# print(ip_does_match_iprange(sys.argv[1], sys.argv[2]))
# try:
# 	print(port_does_match_portrange(sys.argv[3], sys.argv[4]))
# except Exception as e:
# 	print(type(e))
# 	print(e)

if __name__ == '__main__':
	main()
