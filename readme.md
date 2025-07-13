# 🔏 Ring Signature 

Ring signatures and group signatures are both cryptographic primitives that allow a message to be signed on behalf of a group. But they differ in structure, trust model, and anonymity guarantees.

This project demonstrates the creation and verification of **ring signatures** using RSA keys. A ring signature allows a signer to sign a message on behalf of a group (ring) in a way that:
- The signature is verifiable as coming from the group,
- But the actual signer remains anonymous within the group.

Signer wants to sign a message from the group. He initially generates a random value v, and generates random values (s_i) for each of the other participants, but takes his own secret key (s_i and uses it to determine a different secret key, and which reverse of the encryption function. 

Each of the random values for the other participants are encrypted with the public key of the given participant. 

Signer computes the value of y_s in order to create the ring (the result of the ring must equal v). He will inverse this value to produce the equivalent private key (x_s). Signer releases the overall signature, and the random x values, along with the computed secret key. 

1. Generate encryption with k = Hash(message) 
Note: Signer takes the message and takes a hash of it, and creates a key (k).
This key will be used with symmetric encryption to encrypt each of the elements of the ring (E_k, and each element of the ring uses an XOR function from the previous element.

This is a symmetric key (e.g., 256-bit) used for lightweight operations like XOR chaining. It’s not RSA.

2. Generate a random value (u).
Let $$\ u ∈ {0,1}^k \$$ be a random bitstring of same size as key 𝑘.

3. Encrypt u to give $$\ v = E_k(u) \$$.

Encrypt u with Symmetric Key

Compute $$\ v \$$ using XOR:

$$\
v = E_k(u) = k \oplus u
\$$

This value will be updated during the ring creation.

4. For each person (apart from the sender):
	4.1. Calculate $$\ e = s_i ^{Pi} (mod N_i) \$$ and where $$\ s_i \$$ is the random number generated for the secret key of the ith party, and $$\ P_i \$$ is the public key of the party.
	4.2 Calculate $$\ v = v⊕e \$$

🧮 Step 4: Simulate Encryption for All Other Members

For each participant $$ i \neq z $$:

1. Choose a random value:

$$\
s_i \in \mathbb{Z}_{N_i}^*
\$$

2. Simulate public encryption:

$$\
e_i = s_i^{e_i} \mod N_i
\$$

3. Update $$\ v \$$ via XOR chaining:

$$\
v = v \oplus e_i
\$$

---

5. For the signed party (z), calculate $$\ s_z = (v⊕u)^d (mod N_z) \$$ and where d is the secret key of the signing party.

We will end up with the signature (v=Ek(u)), and which completes the ring.

Compute the Real Signer's Value

To complete the ring, compute the actual signer's value $$\ s_z \$$:

$$\
s_z = (v \oplus u)^{d_z} \mod N_z
\$$

This ensures the total XOR chain wraps around correctly.

---

✅ Final Signature Output

The final signature consists of:

- The list $$\ \{ s_0, s_1, \dots, s_{n-1} \} \$$
  - Where only $$\ s_z \$$ was computed using the private key,
  - All other $$\ s_i \$$ are random.
- The value $$\ v \$$.

Thus, the signature is:

$$\
\sigma = (v, \{ s_i \})
\$$

---

To check the signature, the receiver computes the ring, and checks that the result matches the sent signature.

🔍 Signature Verification

To verify a signature $$\ \sigma = (v, \{ s_i \}) \$$ on message $$\ M \$$:

1. Recompute the symmetric key:

$$\
k = \text{Hash}(M)
\$$

2. Recover $$\ u \$$:

$$\
u = D_k(v) = k \oplus v
\$$

3. For each $$\ i \$$, compute:

$$\
e_i' = s_i^{e_i} \mod N_i
\$$

4. Recompute $$ v' $$ via chaining:

$$\
v' = e_0' \oplus e_1' \oplus \dots \oplus e_{n-1}' \oplus u
\$$

5. Check if:

$$\
v' = v
\$$

If this holds, the signature is valid.

---


✅ The actual signer is designated by index signer_index passed to .sign().

🛠️ To add more signers, just increase num_participants and provide more RSA keys via generate_rsa_keys(...).

✅ The real signer’s signature uses their private key (.d), others are simulated with public keys.

🔒 Ring signature preserves anonymity — verifier cannot tell who signed; this index is only known to the signer.

Each member in the ring holds an RSA key pair. The real signer uses their private key, while the rest are simulated with public keys to form a verifiable signature.

The verifier can check that someone in the group signed the message — but not who.


| Step | Description                                                                                                   |
| ---- | ------------------------------------------------------------------------------------------------------------- |
| 1    | $k = \text{Hash}(M)$                                                                                          |
| 2    | Generate random $u$, then $v = k \oplus u$                                                                    |
| 3    | For each $i \ne z$, pick random $s_i$, compute $e_i = s_i^{e_i} \mod N_i$, update $v \leftarrow v \oplus e_i$ |
| 4    | Signer computes $s_z = (v \oplus u)^{d_z} \mod N_z$                                                           |
| 5    | Signature = $\{ s_i \}, v$                                                                                    |
| 6    | Verifier recovers $u$, recomputes $v$ via chaining, checks match                                              |



### 🧠 Key Concepts
```
RingSignature class implements the ring signature algorithm.

sign(message, signer_index) creates a signature on the message using the actual signer at signer_index.

verify(message, signature) verifies the ring signature against the original message.

The implementation uses SHA-1 and SHA-256 for non-cryptographic hash-based commitments (for simplicity).
```

🧪 Output Example
```
Message: Hello

🔏 Actual signer index: 1
Signature: [cipher, s0, s1, s2, s3]

✅ Verification correct message: True
❌ Verification tampered message: False
```

### 🛡️ Security Notes 
For secure applications:
```
Use constant-time operations,

Employ larger key sizes (e.g., 2048+ bits),

Avoid SHA-1,

Use secure randomness and padding (e.g., OAEP, PSS),

Consider elliptic curve ring signatures (e.g., Ed25519 + MLSAG).
```

# Group Signature

⚠️ Note: This is a simplified, insecure prototype for learning. Real group signature schemes (e.g. BBS, BLIND-BBS+, ACJT) require complex zero-knowledge proofs and pairing-based cryptography.


| Feature                   | **Ring Signature**                                           | **Group Signature**                                                           |
| ------------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| **Setup**                 | No centralized authority required                            | Requires a trusted group manager (central authority)                          |
| **Anonymity**             | **Unconditional** anonymity — signer is never identifiable   | **Conditional** anonymity — signer identity can be revealed by group manager  |
| **Revocation**            | Not supported — no way to revoke or remove members           | Supported — group manager can revoke members                                  |
| **Signature Size**        | Generally larger; scales with group size                     | Can be more compact depending on scheme                                       |
| **Membership Management** | Ad hoc: any signer can create their own group of public keys | Formal: group manager controls who joins                                      |
| **Linkability**           | Usually unlinkable unless linkable variant used              | Can be linkable or unlinkable depending on the scheme                         |
| **Signer Accountability** | No one (not even verifier) can identify signer               | Group manager can identify signer if necessary                                |
| **Use Case**              | Whistleblowing, ad hoc anonymity, plausible deniability      | Anonymous authentication with accountability (e.g., voting, anonymous access) |

🔐 Ring Signatures
```
Invented by Rivest, Shamir, and Tauman (2001).

A signer selects a set of public keys (including their own) and signs anonymously.

No interaction or setup required from other group members.

All public keys are treated equally — anyone verifying the signature cannot tell who signed.
```

> Think of a ring signature like an anonymous letter where the envelope lists several possible authors, but you don't know which one wrote it.

👥 Group Signatures
```
Formal structure introduced by Chaum and van Heyst (1991).

Requires a group manager who issues keys to members and can:

Add/revoke members,

Open signatures to reveal the signer (if needed),

Handle member misbehavior.

Ideal for applications where anonymity is desired but traceability is required in emergencies.

```
> Think of group signatures like employees in a company: they can act anonymously on behalf of the company, but HR can later trace who did what if needed.


