#!/usr/bin/env python

import os, pwd, time, sys
from optparse import OptionParser

IPv4_LOCALHOST = '0100007F'
IP_STATE_LISTEN = '0A'

parser = OptionParser()
parser.add_option('-v', action='store_true', dest='verbose', default=False, help = 'verbose')
parser.add_option('-p', action='append', type=str, dest='proc_files', default=[], help = 'conf file with process whitelisting (can be repeated)')
parser.add_option('-a', action='store', type=int, dest='bin_age', default=[], help = 'min age of running binaries (hours)')
(opts, args) = parser.parse_args(sys.argv[1:])

if os.getuid() != 0:
	print 'Must run as root!'
	sys.exit(1)

def alert(severity, alert_string, variables):
	if severity == 0:
		SEV = 'INFORMATIONAL'
	elif severity == 1:
		SEV = 'CRITICAL'
	elif severity == 2:
		SEV = 'WARNING'
	else:
		SEV = 'WHAT'

	if not severity and not opts.verbose:
		return

	try:
		print '%s(%s) uid:%s user:%s pid:%s exe:%s comm:%s cmdline:%s runtime:%.2fh exeage:%.2fh' % (SEV, alert_string, variables['uid'], variables['user'], variables['pid'], variables['exe'], variables['comm'], variables['cmdline'], variables['runtime'], variables['exeage'])
	except:
		if variables:
			print '%s(%s) %s' % (SEV, alert_string, variables)
		else:
			print '%s! %s' % (SEV, alert_string)


def parse_procs_conf():
	tmp_var_vals = []

	# read conf from conf files
	proc_whitelist_lines = []
	for f in opts.proc_files:
		i = 0
		for line in open(f).readlines():
			i += 1
			line = line.strip()
			if not line or line.startswith('#'):
				continue
			proc_whitelist_lines.append(['%s:%i' % (f, i), line])

	# parse conf into whitelisting array
	PROC_WHITELIST_LINES_EXPLODED = []
	for where, line in proc_whitelist_lines:
		i = line.find('#')
		if i >= 0:
			line = line[:i]
		tmp = [col for col in line.split() if col]
		VARS = tmp[0].lower().split('_')
		nr_vars = len(VARS)
		VALS = tmp[1:nr_vars+1]

		if len(VALS) != nr_vars:
			alert(1, 'Skipping invalid cfg line! %s: %s' % (where, line), {})
			continue

		if (VARS, VALS) in tmp_var_vals:
			raise Exception('line duplicate %s: %s' % (where, line))

		EXTRAS_DICT = {}
		EXTRAS = tmp[nr_vars+1:]
		for extra in EXTRAS:
			var, val = extra.split('=')
			if var in EXTRAS_DICT.keys():
				EXTRAS_DICT[var].append(val.split(':'))
			else:
				EXTRAS_DICT[var] = [val.split(':')]
		PROC_WHITELIST_LINES_EXPLODED.append([VARS, VALS, EXTRAS_DICT, where, line, 0])
		tmp_var_vals.append((VARS, VALS))

	return PROC_WHITELIST_LINES_EXPLODED

def hexip4_to_ip4(hex_ip):
	r = str(int(hex_ip[6:8], 16))
	r += '.' + str(int(hex_ip[4:6], 16))
	r += '.' + str(int(hex_ip[2:4], 16))
	r += '.' + str(int(hex_ip[0:2], 16))
	return r

def get_proc_net_maps():
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
	return [ str(int(parts[1][9:], 16)) for inode, parts in proc_net_map.items() if parts[3] == IP_STATE_LISTEN and parts[1][:8] != IPv4_LOCALHOST]


NOW_EPOCH = time.time()

MY_PID = str(os.getpid())
MY_PPID = str(os.getppid())
#MY_PPPID = [line.split()[1] for line in open('/proc/'+MY_PPID+'/status').readlines() if line.startswith('PPid:') ][0]

ME = [MY_PID, MY_PPID]
#ME = []	#TODO RM

# fetch all running process PIDs, as strings
PIDS = [pid for pid in os.listdir('/proc') if pid.isdigit() and pid not in ME]
PIDS = args

def main():
	procs_invalid = []
	procs_checked = []
	procs_skipped = []
	procs_kernel  = []

	try:
		whitelisting_config = parse_procs_conf()
	except Exception, e:
		alert(1, 'Error parsing conf. %s' % (e), None)
		sys.exit(42)

	proc_net_maps = get_proc_net_maps()

	all_listening_nonlocalhost_tcp4_ports = get_all_listening_nonlocalhost_ip4_ports(proc_net_maps['tcp4'])
	all_listening_nonlocalhost_udp4_ports = get_all_listening_nonlocalhost_ip4_ports(proc_net_maps['udp4'])
	proc_net_maps['tcp4']['all_listening_nonlocalhost_ports'] = all_listening_nonlocalhost_tcp4_ports
	proc_net_maps['udp4']['all_listening_nonlocalhost_ports'] = all_listening_nonlocalhost_udp4_ports

	for pid in PIDS:
		print
		print 'checking pid', pid
		try:
			v = get_process_variables(pid)
			print v['comm']
		except Exception, e:
			alert(0, e, None)
			procs_skipped.append(pid)
			continue

		if proc_is_kernel(v):
			print 'pid is kernel', pid
			procs_kernel.append(pid)
			continue

		procs_checked.append(pid)

		if not check_process_ok(pid, whitelisting_config, proc_net_maps):
			procs_invalid.append(pid)
		else:
			print pid, 'ok'

	print
	print 'checked', procs_checked
	print 'skipped', procs_skipped
	print 'invalid', procs_invalid
	print 'kernel', procs_kernel

	if procs_invalid:
		sys.exit(2)
	else:
		sys.exit(0)


def check_process_ok(pid, whitelisting_config, proc_net_maps):
	try:
		v = get_process_variables(pid)
		ofs = get_process_open_files(pid, proc_net_maps)
	except Exception, e:
		alert(0, e, None)
		return True

	return check_process_variables_files(pid, v, ofs, whitelisting_config, proc_net_maps)


def get_process_variables(pid):
	pid_dir = os.path.join('/proc', pid) + os.sep
	exe = None

	uid = str(os.stat(pid_dir).st_uid)

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
	cmdline = cmdline.replace(' ', '')
	cmdline = cmdline.replace(chr(0), '').strip()[:80]

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
		A regular file contains ['regular', filename]

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

			if inode in proc_net_tcp4_map.keys():
				sock = get_ip4_socket_from_inode(inode, proc_net_tcp4_map)
				open_files['tcp4'].append(sock)
			elif inode in proc_net_udp4_map.keys():
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


def check_process_variables_files(pid, proc_variables, open_files, whitelisting_config, proc_net_maps):
	proc_is_whitelisted = False

	for line_list in whitelisting_config:
		VARS, VALS, EXTRAS_DICT, where, line, hits = line_list

		proc_is_whitelisted = True
		for vr, vl in zip(VARS, VALS):
			
			if vr in ['exe', 'cmdline'] and vl.endswith('>'):
				vl = vl[:-1]
				if not proc_variables[vr].startswith(vl):
					proc_is_whitelisted = False
					break
			elif vr == 'pid':
				if vl[0] == '<':
					if int(pid) < int(vl[1:]):
						pass
					else:
						proc_is_whitelisted = False
						break
				elif vl[0] == '>':
					if int(pid) > int(vl[1:]):
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
					if int(uid) < int(vl[1:]):
						pass
					else:
						proc_is_whitelisted = False
						break
				elif vl[0] == '>':
					if int(uid) > int(vl[1:]):
						pass
					else:
						proc_is_whitelisted = False
						break
				else:
					if int(vl) != int(uid):
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

		all_listening_nonlocalhost_tcp4_ports = proc_net_maps['tcp4']['all_listening_nonlocalhost_ports']
		all_listening_nonlocalhost_udp4_ports = proc_net_maps['udp4']['all_listening_nonlocalhost_ports']

		for file_type in open_files.keys():
			if file_type == 'regular':
				for file in open_files['regular']:
					print 'checking regular file', file
			else:
				for file in open_files[file_type]:
					file_ok = False
					print file

					if file['local_ip4'] == IPv4_LOCALHOST:
						print 'skipping local', file
						continue
					else:
						if file['state'] == IP_STATE_LISTEN:
							if 'NET_LISTEN' in EXTRAS_DICT.keys():
								for ip, port in EXTRAS_DICT['NET_LISTEN']:
									if port == file['local_port']:
										file_ok = True
										break

							if not file_ok:
								alert(1, 'process %s listens on non-localhost port %s' % (comm, local_port), proc_variables)

						else:
							if file['local_port'] in all_listening_nonlocalhost_tcp4_ports:
								if 'NET_CON_IN' in EXTRAS_DICT:
									pass
								else:
									alert(1, 'process %s has an inbound connection to local %s:%s from remote %s:%s in state %s' % (comm, hexip4_to_ip4(local_ip4), local_port, hexip4_to_ip4(remote_ip4), remote_port, state), proc_variables)
							else:
								if 'NET_CON_OUT' in EXTRAS_DICT:
									for ip, port in EXTRAS_DICT['NET_CON_OUT']:
										if port == remote_port:
											ok = True
											break

								if not file_ok:
									if state == '01':
										alert(1, 'process %s has an active outbound connection to remote %s:%s' % (comm, hexip4_to_ip4(remote_ip4), remote_port), proc_variables)
									else:
										alert(1, 'process %s has/had an outbound connection to remote %s:%s, now in state %s' % (comm, hexip4_to_ip4(remote_ip4), remote_port, state), proc_variables)

	return proc_is_whitelisted




		# elif of.startswith('/etc'):
		# 	alert(2, 'process has open file in /etc, of=%s' % (of), proc_variables)
		# else:
		# 	pass



if __name__ == '__main__':
	main()
