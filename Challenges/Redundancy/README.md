# Redundancy (vsCTF 2023)
This challenge is a twist on two standard RSA attacks. Each one individually is not enough to break the system, but chaining them in the right way makes decryption possible. Specifically:
- A message is encrypted twice with a common modulus but **without** the two public exponents being coprime.
- A short, known prefix is added to the message before encryption.
Since the public exponents are not coprime, the standard "common modulus" attack cannot be used to directly recover the message. It can, however, be employed to caclulate the encryption of the initial message as if it were encrypted with the gcd of the two actual exponents. This, enables a Coppersmith short-pad attack to be carried out, by significantly decreasing the degree of the polynomial.