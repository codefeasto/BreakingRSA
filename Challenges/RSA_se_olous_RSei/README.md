## RSA se olous RSei (NTUAH4CK 3.0)

This RSA challenge combines an unconventinal method of encoding messages as integers, as well as using a small public exponent (e = 3).

More specifically:

$ m = \prod_{i=1}^{\text{LEN}} \left( s_i^{f_{\text{LEN}-i}} \mod n \right ) $ , 

where $f$ is the flag byte array and LEN is the flag length.

To attack it, the RSA homomorphic properties can be leveraged, in combination with known properties of the plaintext format. This enables us to "chip" away bytes both by the flag format (`NH4CK{...}`), and the fact that $f_i > 32 $

Multiplying with the inverse of $s_i^{32}$ and the inverse of the flag format, leaves us with minimal bruteforce to be done.