#!/usr/bin/python
import sys
import os
import re
import string
import ldap
import tempfile
import time
from datetime import date
if not tempfile.__dict__.has_key('mkstemp'):
	print "you are using an old tempfile!"
	tempfile.mkstemp=tempfile.mktemp


class record:
	pass

config=record()

config.uri="ldap://127.0.0.1:389"
config.userdn=""
config.userpass=""
config.basedn=None
config.filter="objectclass=*"
config.scope="sub"
config.sshappend=0
config.dopgident=0
config.pgconfdir="/etc/postgres"
config.pguserattrib="uid"
config.pgmapname="ldap"
config.dossh=0
config.sshpathpattern="./output/%s/.ssh/authorized_keys"
config.dopgp=0
config.pgpappend=0
config.pgppathpattern="./output/%s/mykeys.pgp"
config.dossl=0
config.sslappend=0
config.sslpathpattern="./output/%s/mykeys.pem"
config.docacert=0
config.cacertpathpattern="./output/ca/keys/cacert.%d.pem"
config.docacrl=0
config.cacrlpathpattern="./output/ca/crls/cacrl.%d.pem"
config.docapgp=0
config.capgppathpattern="./output/ca/pgpkeys/%d.pgp"
config.verbose=0

scopes= {
"base"	: ldap.SCOPE_BASE,
"onelevel"	: ldap.SCOPE_ONELEVEL,
"subtree"	: ldap.SCOPE_SUBTREE,
"sub"	: ldap.SCOPE_SUBTREE
}

def printhelp():
	print """
usage: %s <options>
We accept options in the forms:
	--name
	--name=value
We have the following options:
	help: this help
	uri:	the uri of the ldap server. Default: ldap://127.0.0.1:389/
	userdn:	user dn to bin as. Default: ""
	userpass: user password to bind with. Default: ""
	basedn: base dn for search. You should give this.
	filter: ldap filter expression. default: "objectclass=*"
	scope: scope of the search (base, onelevel, subtree)
		default: subtree
	dossh: Extract ssh public keys. Default is yes.
	sshpathpattern: The path pattern for the ssh public keys.
		Default is "./output/%%s/.ssh/authorized_keys"
	sshappend: Not overwrite ssh public keys but append. Default is false.
	dopgp: Extract pgp public keys. Default is yes.
	pgppathpattern: The path pattern for the pgp public keys.
		Default is "./output/%%s/mykeys.pgp
	pgpappend: Not overwrite pgp public keys but append. Default is false.
	dossl: Extract ssl public keys. Default is yes.
	sslpathpattern: The path pattern for the ssl certs.
		Default is "./output/%%s/%%s/mykeys.pem"
	sslappend: Not overwrite ssh certs but append. Default is false.
	docacert: Get CA certificates. You want to use it with one dn.
	cacertpathpattern: The path pattern for the ca certs.
		Default is "./output/ca/keys/cacert.%%d.pem"
	docacrl: Get CA CRLs. You want to use it with one dn.
	cacrlpathpattern: The path pattern for the ca CRLs.
		Default is "./output/ca/crls/cacrl.%%d.pem"
	docapgp: Get CA pgp public keys. You want to use it with one dn.
	capgppathpattern: The path pattern for the ca pgp public keys.
		Default is "./output/ca/pgpkeys/%%d.pgp"
	capath:	the CA path for verification of certs used for ssh keys
	dopgident: Extract the postgres identity map to <pgconfdir>/pg_ident.d/0<pgmapname> and cat <pgconfdir>/pg_ident.d/[0-9]* > <pgconfdir>/pg_ident.cof
	pgconfdir: The directory containing pg_ident.conf and pg_ident.d
		Default is "/etc/postgres"
	pguserattrib: The postgres username attribute. Default is uid
	pgmapname: The pg_ident map name
	shadowcheck: whether to do shadow account expiration check
	verbose: verbose output
	 """%sys.argv[0]
	sys.exit(1)

def booleanparam(name):
	value=config.__dict__[name]
	#print name,value
	try:
		value=int(value)
		config.__dict__[name]=value
		return
	except ValueError:
		pass
	if len(value) == 0:
		config.__dict__[name]=1
	elif ( value[0]=='i' ) or ( value[0]== 'y' ):
		config.__dict__[name]=1
	else:
		config.__dict__[name]=0

def getconfig():
	for arg in sys.argv[1:]:
		if arg[:2] == "--":
			try:
				(name,value)=string.split(arg[2:],"=",1)
			except ValueError:
				name=arg[2:]
				value=1
			#print name,value
			if name == "help":
				printhelp()
			config.__dict__[name]=value
		else:
			print "we do not have non-option arguments like %s"%(arg,)
			printhelp()
	booleanparam("sshappend")
	booleanparam("sslappend")
	booleanparam("pgpappend")
	booleanparam("dossh")
	booleanparam("dopgident")
	booleanparam("dossl")
	booleanparam("dopgp")
	booleanparam("verbose")
	booleanparam("shadowcheck")
	if not config.uri:
		print "you should give an URI"
		printhelp()
	if not config.basedn:
		print "you should give base DN"
		printhelp()
	try:
		config.scope=scopes[config.scope]
	except KeyError:
		print "invalid scope given: %s"%(config.scope)

def createdirsfor(outfile):
	outpath=string.join(string.split(outfile,"/")[:-1],"/")
	try:
		os.makedirs(outpath)
	except OSError,value:
		if 17 != value.errno:
			"""
			17 is that the dir already exists. If there are an other
			error, we print it and bail out.
			"""
			print value
			sys.exit(1)

def writesshkey(ldaprecord,dn):
	#print ldaprecord
	outfile=config.sshpathpattern%(ldaprecord['uid'][0])
	createdirsfor(outfile)
	if not config.sshappend:
		try:
			os.stat(outfile)
		except OSError, value:
			if value.errno != 2:
				print value
				sys.exit(1)
		else:
			os.unlink(outfile)
	certs=[]
	if ldaprecord.has_key('userCertificate;binary'):
		certs=certs+ldaprecord['userCertificate;binary']
	if ldaprecord.has_key('userCertificate'):
		certs=certs+ldaprecord['userCertificate']
	for cert in certs:
		tf=tempfile.mkstemp(".getkey")[1]
		tfp="%s.pem"%tf
		certfile=open(tf,"w")
		certfile.write(cert)
		certfile.close()
		cmd="openssl x509 -inform der -outform pem <%s >%s"%(tf,tfp)
		res=os.system(cmd)
		if res:
			print "There are some problems converting the key for %s.\n See if openssl and x509toOpenSSH are available in the path.\nThe command line used:\n%s\n"%(dn,cmd)
		os.unlink(tf)
		if not checkcert(tfp):
			os.unlink(tfp)
			continue
		cmd="x509toOpenSSH <%s >>%s"%(tfp,outfile)
		res=os.system(cmd)
		if res:
			print "There are some problems converting the key for %s.\n See if openssl and x509toOpenSSH are available in the path.\nThe command line used:\n%s\n"%(dn,cmd)
			sys.exit(1)
		os.unlink(tfp)

def checkcert(fname):
    """
    returns true if the certificate is okay, false otherwise
    """
    cmd="openssl verify -purpose sslclient -CApath %s %s"%(config.capath,fname)
    if config.verbose > 3:
         print cmd
    out=os.popen(cmd,"r")
    r = out.readlines()
    cv = out.close()
    if config.verbose > 2:
        print "cv=",cv
    if None != cv:
        print "cv=",cv
        return False
    for line in r:
        if config.verbose > 3:
             print "--", line
        if re.search("error",line):
            return False
        if re.search(": OK",line):
            return True
    return False


def writepgpkey(ldaprecord,dn):
	#print ldaprecord
	outfile=config.pgppathpattern%(ldaprecord['uid'][0])
	createdirsfor(outfile)
	if config.pgpappend:
		mode="a"
	else:
		mode="w"
	certs=[]
	if ldaprecord.has_key('pgpKey;binary'):
		certs=certs+ldaprecord['pgpKey;binary']
	if ldaprecord.has_key('pgpKey'):
		certs=certs+ldaprecord['pgpKey']
	certfile=open(outfile,mode)
	for cert in certs:
		certfile.write(cert)
	certfile.close()


def writesslkey(ldaprecord,dn):
	#print ldaprecord
	outfile=config.sslpathpattern%(ldaprecord['uid'][0])
	createdirsfor(outfile)
	if not config.sslappend:
		try:
			os.stat(outfile)
			os.unlink(outfile)
		except OSError, value:
			if value.errno != 2:
				print value
				sys.exit(1)
	certs=[]
	if ldaprecord.has_key('userCertificate;binary'):
		certs=certs+ldaprecord['userCertificate;binary']
	if ldaprecord.has_key('userCertificate'):
		certs=certs+ldaprecord['userCertificate']
	for cert in certs:
		tf=tempfile.mkstemp(".getkey")[1]
		certfile=open(tf,"w")
		certfile.write(cert)
		certfile.close()
		cmd="openssl x509 -inform der -text -outform pem <%s >>%s"%(tf,outfile)
		res=os.system(cmd)
		if res:
			print "There are some problems converting the key for %s.\n See if openssl and x509toOpenSSH are available in the path.\nThe command line used:\n%s\n"%(dn,cmd)
			sys.exit(1)
		os.unlink(tf)


def writecacrl(ldaprecord,dn):
	certs=[]
	if ldaprecord.has_key('certificateRevocationList;binary'):
		certs=certs+ldaprecord['certificateRevocationList;binary']
	if ldaprecord.has_key('certificateRevocationList'):
		certs=certs+ldaprecord['certificateRevocationList']
	number=0
	for cert in certs:
		outfile=config.cacrlpathpattern%(number,)
		createdirsfor(outfile)
		number=number+1
		tf=tempfile.mkstemp(".getkey")[1]
		certfile=open(tf,"w")
		certfile.write(cert)
		certfile.close()
		cmd="openssl crl -inform der -text -outform pem <%s >>%s"%(tf,outfile)
		res=os.system(cmd)
		if res:
			print "There are some problems converting the key for %s.\n See if openssl and x509toOpenSSH are available in the path.\nThe command line used:\n%s\n"%(dn,cmd)
			sys.exit(1)
		os.unlink(tf)

def writecacert(ldaprecord,dn):
	certs=[]
	if ldaprecord.has_key('cACertificate;binary'):
		certs=certs+ldaprecord['cACertificate;binary']
	if ldaprecord.has_key('cACertificate'):
		certs=certs+ldaprecord['cACertificate']
	number=0
	for cert in certs:
		outfile=config.cacertpathpattern%(number,)
		createdirsfor(outfile)
		number=number+1
		tf=tempfile.mkstemp(".getkey")[1]
		certfile=open(tf,"w")
		certfile.write(cert)
		certfile.close()
		cmd="openssl x509 -inform der -text -outform pem <%s >>%s"%(tf,outfile)
		res=os.system(cmd)
		if res:
			print "There are some problems converting the key for %s.\n See if openssl and x509toOpenSSH are available in the path.\nThe command line used:\n%s\n"%(dn,cmd)
			sys.exit(1)
		os.unlink(tf)

def writecapgp(ldaprecord,dn):
	certs=[]
	if ldaprecord.has_key('pgpKey;binary'):
		certs=certs+ldaprecord['pgpKey;binary']
	if ldaprecord.has_key('pgpKey'):
		certs=certs+ldaprecord['pgpKey']
	number=0
	for cert in certs:
		outfile=config.capgppathpattern%(number,)
		createdirsfor(outfile)
		number=number+1
		certfile=open(outfile,"w")
		certfile.write(cert)
		certfile.close()

def shadowcheckfilter(filter):
	t=time.localtime(time.time())
	nowdate=date(t.tm_year,t.tm_mon,t.tm_mday)
	epoch=date(1970,1,1)
	days=(nowdate-epoch).days
	filter="(&(%s)(|(shadowExpire=-1)(shadowExpire>=%u)))"%(filter,days)
	if config.verbose > 4:
		print filter
	return filter

#config.dopgident=0
#config.pgconfdir=/etc/postgres
#config.pguserattrib=uid
#config.pgmapname=ldap
#	dopgident: Extract the postgres identity map to <pgconfdir>/pg_ident.d/0<pgmapname> and cat <pgconfdir>/pg_ident.d/[0-9]* > <pgconfdir>/pg_ident.cof

def writepgident(ldaprecord,dn,pgfile):
	#print ldaprecord
	name=ldaprecord['uid'][0]
	pgname=ldaprecord[config.pguserattrib][0]
	pgfile.write("%s\t%s\t%s\n"%(config.pgmapname,name,pgname))

def main():
	if config.verbose > 6:
		print config.__dict__
	l = ldap.initialize(config.uri)
	l.simple_bind_s(config.userdn,config.userpass)
	filter = config.filter
	if config.shadowcheck:
		filter=shadowcheckfilter(filter)
	res=l.search_s(config.basedn, config.scope,filter )

	if config.dopgident:
		pgfile=open("%s/pg_ident.d/0%s"%(config.pgconfdir,config.pgmapname),"w")

	for l in res:
		dn=l[0]
		if config.verbose:
			print dn
		rec=l[1]
		if rec.has_key('uid'):
			if config.dossh:
				writesshkey(rec,dn)
			if config.dossl:
				writesslkey(rec,dn)
			if config.dopgp:
				writepgpkey(rec,dn)
			if config.dopgident:
				writepgident(rec,dn,pgfile)
		if config.docacert:
			writecacert(rec,dn)
		if config.docacrl:
			writecacrl(rec,dn)
		if config.docapgp:
			writecapgp(rec,dn)
	if config.dopgident:
		pgfile.close()
		cmd="cat %s/pg_ident.d/[0-9]* >%s/pg_ident.conf"%(config.pgconfdir,config.pgconfdir)
		res=os.system(cmd)
		if res:
			print "There are some problems merging pg_ident.conf\nThe command line used:\n%s\n"%(cmd)

if __name__ == "__main__":
	getconfig()
	main()

