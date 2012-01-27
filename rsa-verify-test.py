private = """
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANQNY7RD9BarYRsmMazM1hd7a+u3QeMPFZQ7Ic+BmmeWHvvVP4Yj
yu1t6vAut7mKkaDeKbT3yiGVUgAEUaWMXqECAwEAAQJAIHCz8h37N4ScZHThYJgt
oIYHKpZsg/oIyRaKw54GKxZq5f7YivcWoZ8j7IQ65lHVH3gmaqKOvqdAVVt5imKZ
KQIhAPPsr9i3FxU+Mac0pvQKhFVJUzAFfKiG3ulVUdHgAaw/AiEA3ozHKzfZWKxH
gs8v8ZQ/FnfI7DwYYhJC0YsXb6NSvR8CIHymwLo73mTxsogjBQqDcVrwLL3GoAyz
V6jf+/8HvXMbAiEAj1b3FVQEboOQD6WoyJ1mQO9n/xf50HjYhqRitOnp6ZsCIQDS
AvkvYKc6LG8IANmVv93g1dyKZvU/OQkAZepqHZB2MQ==
-----END RSA PRIVATE KEY-----
"""    
message = "python-crypto sucks"

# Use EVP api to sign message
from M2Crypto import EVP
key = EVP.load_key_string(private)
# if you need a different digest than the default 'sha1':
key.reset_context(md='sha256')
key.sign_init()
key.sign_update(message)
signature = key.sign_final()

# Use EVP api to verify signature
public = """
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANQNY7RD9BarYRsmMazM1hd7a+u3QeMP
FZQ7Ic+BmmeWHvvVP4Yjyu1t6vAut7mKkaDeKbT3yiGVUgAEUaWMXqECAwEAAQ==
-----END PUBLIC KEY-----
""" 
from M2Crypto import BIO, RSA, EVP
bio = BIO.MemoryBuffer(public)
rsa = RSA.load_pub_key_bio(bio)
pubkey = EVP.PKey()
pubkey.assign_rsa(rsa)
pubkey.reset_context(md="sha256")
pubkey.verify_init()
pubkey.verify_update(message)
assert pubkey.verify_final(signature) == 1
