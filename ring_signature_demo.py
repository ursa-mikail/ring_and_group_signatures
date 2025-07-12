# !pip install pycryptodome

import os
import hashlib
import random
from Crypto.PublicKey import RSA
from functools import reduce

class RingSignature:
    def __init__(self, public_keys, key_size=1024):
        self.public_keys = public_keys  # List of RSA keys
        self.key_size = key_size
        self.num_signers = len(public_keys)
        self.q = 1 << (key_size - 1)  # Large prime bound for random values

    def sign(self, message, signer_index):
        """
        Create a ring signature on `message` by signer at `signer_index`.
        """
        self._set_permutation_parameter(message)

        s = [None] * self.num_signers
        u = random.randint(0, self.q)
        c = v = self._E(u)

        # Loop over all indices in ring order starting after the real signer
        indices = list(range(signer_index + 1, self.num_signers)) + list(range(signer_index))
        for i in indices:
            s[i] = random.randint(0, self.q)
            e = self._g(s[i], self.public_keys[i].e, self.public_keys[i].n)
            v = self._E(v ^ e)
            if (i + 1) % self.num_signers == 0:
                c = v  # Close the ring

        # Actual signer computation using private key
        real_key = self.public_keys[signer_index]
        s[signer_index] = self._g(v ^ u, real_key.d, real_key.n)

        return [c] + s

    def verify(self, message, signature):
        """
        Verifies the ring signature for the message.
        """
        self._set_permutation_parameter(message)
        c = signature[0]
        s = signature[1:]

        def compute_e(i):
            return self._g(s[i], self.public_keys[i].e, self.public_keys[i].n)

        y = [compute_e(i) for i in range(self.num_signers)]

        def compute_r(x, i):
            return self._E(x ^ y[i])

        final = reduce(compute_r, range(self.num_signers), c)
        return final == c

    def _set_permutation_parameter(self, message):
        self.permutation = int(hashlib.sha256(message.encode()).hexdigest(), 16)

    def _E(self, x):
        msg = f"{x}{self.permutation}"
        return int(hashlib.sha1(msg.encode()).hexdigest(), 16)

    def _g(self, x, e, n):
        q, r = divmod(x, n)
        if ((q + 1) * n) <= ((1 << self.key_size) - 1):
            return q * n + pow(r, e, n)
        return x


# === Demo ===

def generate_rsa_keys(num_keys, key_size=1024):
    return [RSA.generate(key_size, os.urandom) for _ in range(num_keys)]

def demo_ring_signature():
    message = "Hello"
    tampered_message = "Hello2"
    num_participants = 4
    actual_signer_index = 1  # ← CHANGE this to change the actual signer

    keys = generate_rsa_keys(num_participants)
    ring = RingSignature(keys)

    print("Message:", message)
    signature = ring.sign(message, actual_signer_index)
    print(f"\n🔏 Actual signer index: {actual_signer_index}")
    print("Signature:", signature)

    print("\n✅ Verification correct message:", ring.verify(message, signature))
    print("❌ Verification tampered message:", ring.verify(tampered_message, signature))


if __name__ == "__main__":
    demo_ring_signature()

"""
Message: Hello

🔏 Actual signer index: 1
Signature: [146497213031124629902938747092175609679549429982, 49376631174054100224993588471736298090993330322058615043972879568454271210395833452573025862934530513677015066533776719099318252176617344533447400021702457773061249945533963001253726084630000573565548742192638394293194870737474725515291275083195782253612693269317271773439014939920333291689241956470497934048, 75581347143813616061992682402881426346935386717534851263385369733687817010953815732293854947575401430371570276897817359053162620597879481438780682677531428465032710947285846032794315900145288806188562718451458719802089966364718421201217135891879831252606901351454754257360854621165912288871984708816888585816, 63272238390451527625673964712671382676058486116877219595356181457873318051152725219055679588550658586900212288789314273041221816655115677290994522872556689393923650112689972478637047722223225308418839787895928814093053501479659442980861317775035969396153766847929783138022879570740106209544315137590499036519, 45227830103665456741608946974889166676616886285071119022066223525854065456533215884724532622590140782893195785795128612662154167599529411053551754696444632307237281153413478629527263554955894180929026489220416619312199755410397104387344415869704907791172101323422175324239209572814682473986280850207789102775]

✅ Verification correct message: True
❌ Verification tampered message: False
"""