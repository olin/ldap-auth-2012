import sys, ldap, re, time, getpass

def ldap_auth(server, base, dn, secret):
	try:
		ldap.set_option(ldap.OPT_REFERRALS, 0)
		l = ldap.initialize(SERVER)
		l.protocol_version = 3
		l.simple_bind_s(dn, secret)
		return True
	except ldap.INVALID_CREDENTIALS:
		return False

SERVER = "ldap://ldap.olin.edu"
BASE = "dc=olin,dc=edu"

dn = "MILKYWAY\\" + raw_input("Username: MILKYWAY\\")
secret = getpass.getpass()

print ldap_auth(SERVER, BASE, dn, secret)
