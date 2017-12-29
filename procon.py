#!/usr/bin/env python

import os, pwd, time, sys
from optparse import OptionParser

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

	print '%s(%s) uid:%s user:%s pid:%s exe:%s comm:%s cmdline:%s' % (SEV, alert_string, variables['uid'], variables['user'], variables['pid'], variables['exe'], variables['comm'], variables['cmdline'])

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
		alert(2, 'skipping invalid cfg line: %s' % (line), {'uid':None, 'user':None, 'pid':None, 'exe':None, 'comm':None, 'cmdline':None})
	else:
		EXTRA = tmp[nr_vars+1:]
		PROC_WHITELIST.append([VARS, VALS, EXTRA])


def resolve_socket(inode, proc_net_tcp_map):
	return proc_net_tcp_map[inode]



now_epoch = time.time()

MY_PID = str(os.getpid())
MY_PPID = str(os.getppid())
MY_PPPID = [line.split()[1] for line in open('/proc/'+MY_PPID+'/status').readlines() if line.startswith('PPid:') ][0]

ME = [MY_PID, MY_PPID, MY_PPPID]
ME = []	#TODO RM

# fetch all running process PIDs, as strings
PIDS = [pid for pid in os.listdir('/proc') if pid.isdigit() and pid not in ME]


for pid in PIDS:
	try:
		CRITICALS = []
		WARNINGS = []

		# procs proc dir
		pid_dir = os.path.join('/proc', pid) + os.sep

		# procs UID
		uid = None
		try:
			uid = str(os.stat(pid_dir).st_uid)
		except OSError, e:
			print e
			continue

		# procs user name
		user = None
		try:
			user = pwd.getpwuid(int(uid)).pw_name
		except KeyError:
			user = None
			CRITICALS.append('no matching user for uid %s' % (uid))

		# procs command name
		comm = None
		comm = open(pid_dir + 'comm').read().strip()

		# procs exe file
		exe = None
		try:
			exe = os.readlink(pid_dir + 'exe')
		except OSError:
			if uid == '0':
				#system process
				continue
			print 'proc with no exe and not running as root', pid, uid, user, comm
			raise OSError()

		# procs command line
		cmdline = None
		cmdline = open(pid_dir + 'cmdline').read()
		cmdline = cmdline.replace(' ', '')
		cmdline = cmdline.replace(chr(0), '').strip()[:80]

		print '\nPID: ', pid, uid, user, exe, comm, cmdline

		# executable files age (since last modified)
		exe_age_hours = (now_epoch - os.stat(exe).st_mtime) / 3600

		LOCALS = locals()

		if 'clamscan' in exe:
			alert(2, 'clamscan running', LOCALS)

		if ' (deleted)' in exe:
			alert(1, 'deleted file running', LOCALS)


		proc_is_whitelisted = False
		for whitelist in PROC_WHITELIST:
			#print whitelist
			try:
				VARS = whitelist[0]
				VALS = whitelist[1]
				EXTRA = whitelist[2]

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
						#print 'check pid', pid, vr, vl
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
					else:
						#print 'check', vr, vl, LOCALS[vr]
						if LOCALS[vr] != vl:
							proc_is_whitelisted = False
							#print 'break'
							break
						#print 'ok'

				vr = 'OPEN FILES'
				vl = None

				# if this whitelisting row whitelisted the process by matching variables, lets check network connections
				if proc_is_whitelisted:
					pid_fd_dir = os.path.join(pid_dir, 'fd') + os.sep

					proc_net_tcp = [ line.split() for line in open('/proc/net/tcp').readlines() ]
					proc_net_tcp_map = {}
					for line in proc_net_tcp:
						proc_net_tcp_map[line[9]] = line

					for ofd in os.listdir(pid_fd_dir):
						of = os.readlink(pid_fd_dir + ofd)
						if of == '/dev/null':
							pass
						elif of.startswith('socket:'):
							inode = of.split('[')[1][:-1]
							if inode in proc_net_tcp_map.keys():
								print resolve_socket(inode, proc_net_tcp_map)
								break
							pass
						elif of.startswith('/etc'):
							alert(2, 'process has open file in /etc, of=%s' % (of), LOCALS)
						else:
							pass

				if proc_is_whitelisted:
					break
			except IOError:
				pass
#			except Exception, e:
#				errstr = 'Problem with %s=%s in whitelisting line %s' %(vr, vl, whitelist)
#				raise Exception(errstr)

		if proc_is_whitelisted:
			pass
		else:
			alert(42, 'ok?', LOCALS)
			break

		#print pid, open(os.path.join('/proc', pid, 'cmdline'), 'rb').read()
	except IOError: # proc has already terminated
		continue
	except Exception, e:
		print e
		sys.exit(2)
