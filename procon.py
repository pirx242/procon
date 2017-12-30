#!/usr/bin/env python

import os, pwd, time, sys
from optparse import OptionParser

IPv4_LOCALHOST = '0100007F'

parser = OptionParser()
parser.add_option('-p', action='append', type=str, dest='proc_file', default=[], help = 'conf file with process whitelisting (can be repeated)')
parser.add_option('-a', action='store', type=int, dest='bin_age', default=[], help = 'min age of running binaries (hours)')
(opts, args) = parser.parse_args(sys.argv[1:])

if os.getuid() != 0:
	print 'Must run as root!'
	sys.exit(1)

# read conf from conf files
proc_whitelist_raw = []
for f in opts.proc_file:
	proc_whitelist_raw = proc_whitelist_raw + [ line.strip() for line in open(f).readlines() if line.strip() and not line.strip().startswith('#') ]

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
		print '%s(%s) %s' % (SEV, alert_string, variables)

# parse conf into whitelisting array
PROC_WHITELIST = []
for line in proc_whitelist_raw:
	i = line.find('#')
	if i >= 0:
		line = line[:i]
	tmp = [col for col in line.split() if col]
	VARS = tmp[0].lower().split('_')
	nr_vars = len(VARS)
	VALS = tmp[1:nr_vars+1]

	if len(VALS) != nr_vars:
		alert(2, 'skipping invalid cfg line: %s' % (line), {})
		continue

	EXTRAS_DICT = {}
	EXTRAS = tmp[nr_vars+1:]
	for extra in EXTRAS:
		var, val = extra.split('=')
		if var in EXTRAS_DICT.keys():
			EXTRAS_DICT[var].append(val.split(':'))
		else:
			EXTRAS_DICT[var] = [val.split(':')]
	PROC_WHITELIST.append([VARS, VALS, EXTRAS_DICT])


def hexip4_to_ip4(hex_ip):
	r = str(int(hex_ip[6:8], 16))
	r += '.' + str(int(hex_ip[4:6], 16))
	r += '.' + str(int(hex_ip[2:4], 16))
	r += '.' + str(int(hex_ip[0:2], 16))
	return r

now_epoch = time.time()

MY_PID = str(os.getpid())
MY_PPID = str(os.getppid())
MY_PPPID = [line.split()[1] for line in open('/proc/'+MY_PPID+'/status').readlines() if line.startswith('PPid:') ][0]

ME = [MY_PID, MY_PPID, MY_PPPID]
ME = []	#TODO RM

# fetch all running process PIDs, as strings
PIDS = [pid for pid in os.listdir('/proc') if pid.isdigit() and pid not in ME]

PROC_NET_TCP4 = [ line.split() for line in open('/proc/net/tcp').readlines() if line.strip()[:2] != 'sl']
PROC_NET_TCP4_MAP = {}
for parts in PROC_NET_TCP4:
	PROC_NET_TCP4_MAP[parts[9]] = parts
#LISTENING_TCP4_SOCKETS = [ [int(parts[1][9:], 16), hexip4_to_ip4(parts[1][:8])] for parts in PROC_NET_TCP4 if parts[3] == '0A']
LISTENING_NONLOCALHOST_TCP4_SOCKETS = [ int(parts[1][9:], 16) for parts in PROC_NET_TCP4 if parts[3] == '0A' and parts[1][:8] != IPv4_LOCALHOST]

#PROC_NET_TCP6 = [ line.split() for line in open('/proc/net/tcp6').readlines() if line.strip()[:2] != 'sl']
#PROC_NET_TCP6_MAP = {}
#for line in PROC_NET_TCP4:
#	PROC_NET_TCP6_MAP[line[9]] = line
#LISTENING_TCP6_SOCKETS = [ int(parts[1][33:], 16) for parts in PROC_NET_TCP6 if parts[3] == '0A']
#print LISTENING_TCP6_SOCKETS

def check_process(pid):
	# procs proc dir
	pid_dir = os.path.join('/proc', pid) + os.sep

	# procs UID
	uid = None
	try:
		uid = str(os.stat(pid_dir).st_uid)
	except OSError, e:
		alert(42, e, locals())
		return False

	# procs user name
	user = None
	try:
		user = pwd.getpwuid(int(uid)).pw_name
	except KeyError:
		user = '<None>'
		alert(1, 'no matching user for uid%s (pid=%s)' % (uid, pid), locals())

	# procs command line
	cmdline = None
	cmdline = open(pid_dir + 'cmdline').read()
	cmdline = cmdline.replace(' ', '')
	cmdline = cmdline.replace(chr(0), '').strip()[:80]

	runtime = (now_epoch - os.stat(pid_dir + 'cmdline').st_mtime) / 3600.0

	# procs command name
	comm = None
	comm = open(pid_dir + 'comm').read().strip()

	# procs exe file
	exe = None
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

	LOCALS = locals()

	print '\nPID: ', pid, uid, user, exe, comm, cmdline


	if 'clamscan' in exe:
		alert(2, 'clamscan running', LOCALS)

	proc_is_whitelisted = False
	for whitelist in PROC_WHITELIST:
		#print whitelist
		try:
			VARS = whitelist[0]
			VALS = whitelist[1]
			EXTRAS_DICT = whitelist[2]

			proc_is_whitelisted = True
			for i in range(len(VARS)):
				vr = VARS[i]
				vl = VALS[i]
				#print vr, vl
				
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
					#print 'check', vr, vl, LOCALS[vr]
					if LOCALS[vr] != vl:
						proc_is_whitelisted = False
						#print 'break'
						break
					#print 'ok'

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
							local_port_decimal = int(local[9:], 16)
							remote_port_decimal = int(remote[9:], 16)
							local_ip4 = local[:8]
							remote_ip4 = remote[:8]

							if state == '0A':
								if local_ip4 == IPv4_LOCALHOST:
									break
								elif 'NET_LISTEN' in EXTRAS_DICT.keys():
									ok = False
									for ip, port in EXTRAS_DICT['NET_LISTEN']:
										if port == str(local_port_decimal):
											ok = True
											break

								if not ok:
									alert(1, 'process %s listens on non-localhost port %i' % (comm, local_port_decimal), LOCALS)

							elif state == '01':
								if remote_ip4 == IPv4_LOCALHOST:
									break
								elif 'NET_CON' in EXTRA:
									break
								alert(1, 'process %s has an active connection between local IP:port %s:%i and remote IP:port %s:%i' % (comm, hexip4_to_ip4(local_ip4), local_port_decimal, hexip4_to_ip4(remote_ip4), remote_port_decimal), LOCALS)

							else:
								if remote_ip4 == IPv4_LOCALHOST:
									break
								elif 'NET_CON' in EXTRA:
									break
								alert(1, 'process %s has a connection between local IP:port %s:%i and remote IP:port %s:%i in state %s' % (comm, hexip4_to_ip4(local_ip4), local_port_decimal, hexip4_to_ip4(remote_ip4), remote_port_decimal, state), LOCALS)

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
		alert(42, 'ok?', LOCALS)
		return False

for pid in PIDS:
	try:
		is_ok = check_process(pid)
		if not is_ok:
			break
	except IOError: # proc has already terminated
		continue
	except Exception, e:
		print e
		sys.exit(2)
