## Redundancy (vsCTF 2023)


This challenge encrypts the same message with the same modulo, but with different exponents $e1, e2$.
Our first key observation is that both exponents are extremely small, and they have 5 as a common factor.

We are also given quit a lot of bytes on the MSB of the message, something that always hints at lattice approaches.

Therefore, we can conclude that this is a twist on two standard RSA attacks. Each one individually is not enough to break the system, but chaining them in the right way makes decryption possible. Specifically:
- A message is encrypted twice with a common modulus but **without** the two public exponents being coprime.
- A known prefix is added to the message before encryption.

Since the public exponents are not coprime, the standard "common modulus" attack cannot be used to directly recover the message. 
However, it can be employed to caclulate the encryption of the initial message as if it were encrypted with the gcd of the two actual exponents.


Thus, it is trivial to calculate $m^5 \mod n$.

In combination with the given prefix, it enables a Coppersmith short-pad attack to be carried out, by significantly decreasing the degree of the polynomial.

Since the flag is so small, it is possible to just iterate through all lengths until small_roots finds a solution. 