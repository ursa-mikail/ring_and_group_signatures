#!pip install pycryptodome
import os
import hashlib
import random
from Crypto.PublicKey import RSA

class GroupManager:
    def __init__(self):
        self.member_keys = []
        self.member_ids = []
        self.revoked = set()

    def enroll_member(self, member_id):
        key = RSA.generate(1024, os.urandom)
        self.member_ids.append(member_id)
        self.member_keys.append(key)
        return key.publickey(), key  # Return public and private parts

    def revoke_member(self, member_id):
        self.revoked.add(member_id)

    def open_signature(self, message, signature):
        for idx, key in enumerate(self.member_keys):
            member_id = self.member_ids[idx]
            if member_id in self.revoked:
                continue
            digest = hashlib.sha256(message.encode()).hexdigest()
            try:
                decrypted = pow(signature, key.e, key.n)
                if decrypted == int(digest, 16) % key.n:
                    return member_id
            except:
                continue
        return None


class GroupSignatureScheme:
    def __init__(self, public_keys, member_ids):
        self.public_keys = public_keys
        self.member_ids = member_ids

    def sign(self, message, member_id, private_key):
        digest = hashlib.sha256(message.encode()).hexdigest()
        sig = pow(int(digest, 16), private_key.d, private_key.n)
        return sig  # Anonymous signature

    def verify(self, message, signature):
        digest = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        for key in self.public_keys:
            try:
                v = pow(signature, key.e, key.n)
                if v == digest % key.n:
                    return True
            except:
                continue
        return False

# Setup group manager
gm = GroupManager()

# Enroll members
pub_keys, priv_keys = [], []
number_of_signers = 10
for i in range(number_of_signers):
    pub, priv = gm.enroll_member(f"user{i}")
    print(f"user{i}", "public key:", pub.export_key())

    pub_keys.append(pub)
    priv_keys.append(priv)

# Create the group signature scheme
gss = GroupSignatureScheme(pub_keys, gm.member_ids)

# Sign a message anonymously as user 1
msg = "This is a secret message."
sig = gss.sign(msg, member_id="user1", private_key=priv_keys[1])

print("\nSignature:", sig)
#gm.revoke_member("user1")
gm.revoke_member("user2")
#gm.revoke_member("user3")

# Verify the signature without knowing who signed
print("✅ Verified?", gss.verify(msg, sig))

# Group manager can open the signature
print("🔓 Signer was:", gm.open_signature(msg, sig))

"""
user0 public key: b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCigG9mOSVRat9UuWXWs96Hfjc3\nfPR1IDAKThs0zmDfp7pptxUrn0QRv2Q74Ljyzji6UM01QgUa0g9h31MuTHWi4z5q\ncfCmspYhikXLtwRyY0o8w3GL1iz0aeYVMknabvyFTkp5oBut1GgxhuchZBY3opCX\nHsdmjMsAUEMNRbtSPQIDAQAB\n-----END PUBLIC KEY-----'
user1 public key: b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvTJZyAxwBTJ/BBJOBvzsnvLWC\nLzZwUafl06wSm47CZWTbViwNDIk7JsZ+V8XNMy8MX4lvjypTVphjfY7xvL0Ml5T7\nMgVViPtUBG2Rs55KKDkjJWNvO7RQiBhpllHjFvCR9yAZtlaFySAiJtCP1MuYoHk/\nh+TKOFkKFfejA2J5pwIDAQAB\n-----END PUBLIC KEY-----'
user2 public key: b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRKsBNbQoO8jW4irskQkNPUP3w\nkytFKILYK2s2BIC8Yx+1bfIwYUrhSZcg8hqLrXqHJEZONIGL064/FS7vfK7xzhQV\nIoOMLZpf7mtkCS4CZzNi6qLg0tszWjML4O2zAbjWfhMx9quoJDGQzsrhNeIyZ/GZ\nifEvkfaSaOLtAePPvwIDAQAB\n-----END PUBLIC KEY-----'
user3 public key: b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJrSJuBqzptNlKoc8o/yX293qZ\nFrLetwDfOMHCoLSzJwtFE/IuWqx7iw9mo9Bn76Ofrn9OjzWVmiZiy5qMNLTlpA0q\nyUuFXwSsLMNPCydFFljooOWbpxaq11/7BnWoRrOj0smpbX2u03QoOAi0JtuVTl0X\nxjSwVzoyY0OlrNPR2QIDAQAB\n-----END PUBLIC KEY-----'
user4 public key: b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDjH1jlE7v9R/h0fZb8/npOafUF\nIwWp/4xzy7KADOntyqvxBeBXz0YsgaFII7PTEW5SUDmYwLiBdKn6rHICXACR3Val\nLvIKTG+pjcc1PtAmvdGTMX29iACwolLnl0xHThkaCTWFW1CAhkh5iHWhQuho+mFU\nO1mru/7JYr6AhZK/qQIDAQAB\n-----END PUBLIC KEY-----'
user5 public key: b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkz2RwD9Vc8cOfHp3jpTDfrp/a\nLrNxa9gKGi2272BP4KZqjIFmmOuU3t5p+cm0kmkxwOqGjITP8lvao/0QdleMotIZ\nXN7mQv/k70CVDQre5cP4X2s5ssYveAjS3zEcs4lcLNMQ9NIlw91dL90Gq5GvouRx\nUba+Rf9TYWsSZCJCjQIDAQAB\n-----END PUBLIC KEY-----'
user6 public key: b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7aTMfRjS1R1adztPdE5McfXHH\nUgbdGQ6KhEvU46ZwgXhYH9EPxrzlc3RPiIZVUKxQKbeNQ5fppv/qyfx7vex1DjDR\nEh+fnLpV+bQlrXmJC8TMBz6y6SJey6FMYQCNkowRgaCKtVexelG8lJ25qUw52cjl\nUlDxvSXZoMeiXKagLwIDAQAB\n-----END PUBLIC KEY-----'
user7 public key: b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0ylQJKKraMgAGQ7z2OuBhRiou\ntdCf8NdFXHDNZPOMIrgKFciPS5bFChtLvYnS38FOP+ouwCIXHdqO/IAY4mEKrPVQ\nELdh0I943rAFi0EfK5zrQ/2DcwGRt0Inh3vENXuvaQdYnDZx3BRrXkzOvPQ/Pshv\n5w1SWcSiNbrOi8yOwQIDAQAB\n-----END PUBLIC KEY-----'
user8 public key: b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWeVnNaCFkeb6kjPmqIQ2LqNUr\nAbSbXB8zG3ZQJ+PWeNjmk/ENohy15ZPwdkgg6NA6kiexXK95xsFI5343DzhRD2Fg\nPRCKZGTt0YV/6IWwY6Fl9a8+v5D0gAEgF894s/wnN7XMS8Mz2HEf6l5+gXH03Stb\nox1CqaHdjT4p+DZDywIDAQAB\n-----END PUBLIC KEY-----'
user9 public key: b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDP//KQfJuB1firu0XmlSxwuyxC\n4fV/uenZXbYfCK/VbLc4bOzwli6GdnAourFgXOxMzvdl/ExD86+2y19NpxZ1EwNG\nyT1LpVFv/GOg4L1rj9D+Xi+ycNsjR42A5xrdpLN8fGsTktUGmhyghMUDYh6/7khY\nifOAXSyF5aRoLgPjBQIDAQAB\n-----END PUBLIC KEY-----'

Signature: 97847362459968341143801144537976272453553574049748182154397681820487244375181955475565012209699445991499282972602768552919308630710311673271197998293121919734087675101011526242940572250944639357348429869190273880418612150404200880892219681967016179648513437018442473767353728701142798062944847157379851061388
✅ Verified? True
🔓 Signer was: user1


"""