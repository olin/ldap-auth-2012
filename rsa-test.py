import base64, re
from M2Crypto import RSA

PUB_KEY = RSA.load_pub_key("olinauth-pub.pem")
PRIV_KEY = RSA.load_key("olinauth-priv.pem")

def get_username(ctxt):
	try:
		ptxt = PUB_KEY.public_decrypt(ctxt, 1)
		pat = re.compile(r'(?P<length>[0-9]+)#(?P<name>.*)')
		nlen, name = pat.match(ptxt).groups()
		if len(name) != int(nlen):
			return None
		return name
	except:
		return None

ctxt = PRIV_KEY.private_encrypt("5#tryan", 1)
print get_username(ctxt)
