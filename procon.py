#!/usr/bin/env python

import os, pwd, time, sys
from optparse import OptionParser

IPv4_LOCALHOST = '0100007F'

parser = OptionParser()
parser.add_option('-v', action='store_true', dest='verbose', default=False, help = 'verbose')
parser.add_option('-p', action='append', type=str, dest='proc_file', default=[], help = 'conf file with process whitelisting (can be repeated)')
parser.add_option('-a', action='store', type=int, dest='bin_age', default=[], help = 'min age of running binaries (hours)')
(opts, args) = parser.parse_args(sys.argv[1:])

if os.getuid() != 0:
	print 'Must run as root!'
	sys.exit(1)

# read conf from conf files
proc_whitelist_lines = []
for f in opts.proc_file:
	i = 0
	for line in open(f).readlines():
		i += 1
		line = line.strip()
		if not line or line.startswith('#'):
			continue
		proc_whitelist_lines.append(['%s:%i' % (f, i), line])

def alert(severity, alert_string, variables):
	if severity == 1:
		SEV = 'CRITICAL'
	elif severity == 2:
		SEV = 'WARNING'
	else:
		SEV = 'WHAT'

	try:
		print '%s(%s) uid:%s user:%s pid:%s exe:%s comm:%s cmdline:%s runtime:%.2fh exeage:%.2fh' % (SEV, alert_string, variables['uid'], variables['user'], variables['pid'], variables['exe'], variables['comm'], variables['cmdline'], variables['runtime'], variables['exeage'])
	except:
		if variables:
			print '%s(%s) %s' % (SEV, alert_string, variables)
		else:
			print '%s! %s' % (SEV, alert_string)

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
		alert(2, 'Skipping invalid cfg line! %s: %s' % (where, line), {})
		continue

	EXTRAS_DICT = {}
	EXTRAS = tmp[nr_vars+1:]
	for extra in EXTRAS:
		var, val = extra.split('=')
		if var in EXTRAS_DICT.keys():
			EXTRAS_DICT[var].append(val.split(':'))
		else:
			EXTRAS_DICT[var] = [val.split(':')]
	PROC_WHITELIST_LINES_EXPLODED.append([VARS, VALS, EXTRAS_DICT, where, line, 0])

def hexip4_to_ip4(hex_ip):
	r = str(int(hex_ip[6:8], 16))
	r += '.' + str(int(hex_ip[4:6], 16))
	r += '.' + str(int(hex_ip[2:4], 16))
	r += '.' + str(int(hex_ip[0:2], 16))
	return r

now_epoch = time.time()

MY_PID = str(os.getpid())
MY_PPID = str(os.getppid())
#MY_PPPID = [line.split()[1] for line in open('/proc/'+MY_PPID+'/status').readlines() if line.startswith('PPid:') ][0]

ME = [MY_PID, MY_PPID]
#ME = []	#TODO RM

# fetch all running process PIDs, as strings
PIDS = [pid for pid in os.listdir('/proc') if pid.isdigit() and pid not in ME]

PROC_NET_TCP4 = [ line.split() for line in open('/proc/net/tcp').readlines() if line.strip()[:2] != 'sl']
PROC_NET_TCP4_MAP = {}
for parts in PROC_NET_TCP4:
	PROC_NET_TCP4_MAP[parts[9]] = parts
LISTENING_NONLOCALHOST_TCP4_SOCKETS = [ int(parts[1][9:], 16) for parts in PROC_NET_TCP4 if parts[3] == '0A' and parts[1][:8] != IPv4_LOCALHOST]

ALL_LISTENING_PORTS = []
for parts in PROC_NET_TCP4:
	local = parts[1]
	state = parts[3]
	local_port = str(int(local[9:], 16))
	local_ip4 = local[:8]

	if state != "0A":
		continue

	if local_ip4 == IPv4_LOCALHOST:
		continue

	ALL_LISTENING_PORTS.append(local_port)


def check_process(pid):
	# procs proc dir
	pid_dir = os.path.join('/proc', pid) + os.sep

	# procs UID
	try:
		uid = str(os.stat(pid_dir).st_uid)
	except OSError, e:
		alert(42, e, locals())
		return False

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
				status_state = line.split(' ', 1)[1]
	del line


	if status_state.startswith('Z'):
		alert(2, 'zombie process', locals())

	# procs command line
	cmdline = open(pid_dir + 'cmdline').read()
	cmdline = cmdline.replace(' ', '')
	cmdline = cmdline.replace(chr(0), '').strip()[:80]

	runtime = (now_epoch - os.stat(pid_dir + 'cmdline').st_mtime) / 3600.0

	# procs command name
	comm = open(pid_dir + 'comm').read().strip()

	# procs exe file
	exeage = 0.0
	try:
		exe = os.readlink(pid_dir + 'exe')
		if ' (deleted)' in exe:
			exeage = (now_epoch - os.stat(exe[:-10]).st_mtime) / 3600.0
			alert(1, 'deleted file running', locals())
			exe = exe[:-10]
		else:
			# executable files age (since last modified)
			exeage = (now_epoch - os.stat(exe).st_mtime) / 3600.0
	except OSError:
		if uid == '0':
			#kernel process
			return True
		else:
			alert(1, 'proc with no exe and not running as root', locals())
			return False

	proc_is_whitelisted = False
	for whitelist in PROC_WHITELIST_LINES_EXPLODED:
		try:
			VARS = whitelist[0]
			VALS = whitelist[1]
			EXTRAS_DICT = whitelist[2]
			WHERE = whitelist[3]
			LINE = whitelist[4]
			HITS = whitelist[5]

			LOCALS = locals()

			proc_is_whitelisted = True
			for i in range(len(VARS)):
				vr = VARS[i]
				vl = VALS[i]
				
				if vr in ['exe', 'cmdline'] and vl.endswith('>'):
					vl = vl[:-1]
					if not LOCALS[vr].startswith(vl):
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
					if LOCALS[vr] != vl:
						proc_is_whitelisted = False
						break

			vr = 'OPEN FILES'
			vl = None

			# if this whitelisting row whitelisted the process by matching variables, lets check any network connections
			if proc_is_whitelisted:
				pid_fd_dir = os.path.join(pid_dir, 'fd') + os.sep

				for ofd in os.listdir(pid_fd_dir):
					of = os.readlink(pid_fd_dir + ofd)
					if of == '/dev/null':
						pass
					elif of.startswith('socket:'):
						inode = of.split('[')[1][:-1]
						if inode in PROC_NET_TCP4_MAP:
							parts = PROC_NET_TCP4_MAP[inode]

							local = parts[1]
							remote = parts[2]
							state = parts[3]
							local_port = str(int(local[9:], 16))
							remote_port = str(int(remote[9:], 16))
							local_ip4 = local[:8]
							remote_ip4 = remote[:8]

							ok = False

							if state == '0A':
								if local_ip4 == IPv4_LOCALHOST:
									break
								elif 'NET_LISTEN' in EXTRAS_DICT.keys():
									for ip, port in EXTRAS_DICT['NET_LISTEN']:
										if port == local_port:
											ok = True
											break

								if not ok:
									alert(1, 'process %s listens on non-localhost port %s' % (comm, local_port), LOCALS)

							else:
								if remote_ip4 == IPv4_LOCALHOST:
									break

								if local_port in ALL_LISTENING_PORTS:
									if 'NET_CON_IN' in EXTRAS_DICT:
										pass
									else:
										alert(1, 'process %s has an inbound connection to local %s:%s from remote %s:%s in state %s' % (comm, hexip4_to_ip4(local_ip4), local_port, hexip4_to_ip4(remote_ip4), remote_port, state), LOCALS)
								else:
									if 'NET_CON_OUT' in EXTRAS_DICT:
										for ip, port in EXTRAS_DICT['NET_CON_OUT']:
											if port == remote_port:
												ok = True
												break

									if not ok:
										if state == '01':
											alert(1, 'process %s has an active outbound connection to remote %s:%s' % (comm, hexip4_to_ip4(remote_ip4), remote_port), LOCALS)
										else:
											alert(1, 'process %s has/had an outbound connection to remote %s:%s, now in state %s' % (comm, hexip4_to_ip4(remote_ip4), remote_port, state), LOCALS)

					elif of.startswith('/etc'):
						alert(2, 'process has open file in /etc, of=%s' % (of), LOCALS)
					else:
						pass

			if proc_is_whitelisted:
				break
		except IOError:
			pass
		#except Exception, e:
			#errstr = 'Problem with %s=%s in whitelisting line %s' %(vr, vl, whitelist)
			#raise Exception(errstr)

	if proc_is_whitelisted:
		return True
	else:
		alert(1, 'bad process', LOCALS)
		return False

nr_bad_processes = 0
for pid in PIDS:
	if not check_process(pid):
		nr_bad_processes += 1

if nr_bad_processes:
	sys.exit(2)
else:
	sys.exit(0)
