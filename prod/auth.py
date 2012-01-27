#!/usr/bin/python

import web, re, datetime, itertools, time, math, os
import cgi, urllib2, simplejson, urllib, ldap, base64
from M2Crypto import RSA

def get_root():
	return "/auth" if web.ctx.host != "0.0.0.0:8080" else ""

web.config.debug = True

urls = (
	'/?', 'index',
	'/logout', 'logout'
)

render = web.template.render('templates', base='base', globals={
	"re": re,
	"time": time,
	"datetime": datetime,
	"itertools": itertools,
	"sum": sum,
	"os": os,

	"get_root": get_root
	})

#######
# LDAP
#######

LDAP_SERVER = "ldap://ldap.olin.edu"

def ldap_auth(server, dn, secret):
	try:
		ldap.set_option(ldap.OPT_REFERRALS, 0)
		l = ldap.initialize(server)
		l.protocol_version = 3
		l.simple_bind_s(dn, secret)
		return True
	except ldap.INVALID_CREDENTIALS:
		return False

###########
# RSA keys
###########

def passphrase_callback(r):
	return "OLINAUTH"

def clear_keys(username):
	try:
		os.unlink("priv/%s.pem" % username)
		os.unlink("pub/%s.pem" % username)
	except OSError:
		pass

def gen_keys(username):
	clear_keys(username)
	r = RSA.gen_key(1024, 161, callback=lambda x : None)
	r.save_key("priv/%s.pem" % username, callback=passphrase_callback)
	r.save_pub_key("pub/%s.pem" % username)

def get_priv_key(username):
	return RSA.load_key("priv/%s.pem" % username, passphrase_callback)

def get_pub_key(username):
	return RSA.load_pub_key("pub/%s.pem" % username)

def hash_username(username):
	ctxt = get_priv_key(username).private_encrypt(str(len(username)) + "#" + username, 1)
	return base64.b64encode(ctxt)

def verify_username(enc, username):
	try:
		ctxt = base64.b64decode(enc)
		ptxt = get_pub_key(username).public_decrypt(ctxt, 1)
		pat = re.compile(r'(?P<length>[0-9]+)#(?P<name>.*)')
		nlen, name = pat.match(ptxt).groups()
		if len(name) != int(nlen):
			return None
		return name == username
	except:
		return None

#########
# routes
#########

def set_auth_cookie(key, value, time):
	for domain in ["apps"]:
		web.setcookie(key, value, expires=time, domain=domain)

def clear_session():
	key = web.cookies().get('olin-auth-key')
	username = web.cookies().get('olin-auth-username')
	if key != None and username != None and verify_username(key, username):
		clear_keys(username)
	set_auth_cookie('olin-auth-key', "", 60*60*24*30)
	set_auth_cookie('olin-auth-username', "", 60*60*24*30)

#
# /
#

class index:

	# main page

	def GET(self):
		i = web.input()
		failed = i.has_key('failed')
		redirect = i['redirect'] if i.has_key('redirect') else ''
		query = "redirect=" + redirect

		key = web.cookies().get('olin-auth-key')
		username = web.cookies().get('olin-auth-username')
		if key != None and username != None and not verify_username(key, username):
			username = None
		if username and redirect:
			return web.seeother(redirect)
		return render.index(username, query, failed)
		
	def POST(self):
		clear_session()
		
		i = web.input()
		username = (i['username'] if i.has_key('username') else '').encode('ascii','ignore')
		password = (i['password'] if i.has_key('password') else '').encode('ascii','ignore')
		redirect = i['redirect'] if i.has_key('redirect') else '/'

		web.header('Content-Type', 'application/json')
		if ldap_auth(LDAP_SERVER, "MILKYWAY\\" + username, password):
			gen_keys(username)
			set_auth_cookie('olin-auth-key', hash_username(username), 60*60*24*30)
			set_auth_cookie('olin-auth-username', username, 60*60*24*30)
			return web.redirect(redirect)
		else:
			return web.seeother('/?failed&redirect=' + redirect)

#class init:
#	def GET(self):


class logout:

	# logout
	def POST(self):
		i = web.input()
		redirect = i['redirect'] if i.has_key('redirect') else '/'

		clear_session()
				
		return web.seeother(redirect)


#########
# launch
#########

app = web.application(urls, globals())
if __name__ == "__main__":
	app.run()
