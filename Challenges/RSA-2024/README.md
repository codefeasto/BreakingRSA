## RSA-2024 (imaginaryCTF monthly - Round 42)

While this initially seems like a simple challenge, it is deceptively complicated, since we aren't given the value of e. 
To solve it, it is required to approach RSA in an unconventional means. While we are used to thinking about the order of the group used in standard RSA instances using Euler's phi, the key to solving the challenge is to instead utilize Carmichael's lambda function. 

Since this value divides phi, and the server doesn't check in any way that the modulus N we provide is the product of two primes, we can instead construct a "malicious" value of N, with as small Carmichael's lambda as possible. Finally, since the value of lambda is so small, then we can enumerate all possible values of the secret exponent, and attemp to decrypt the message until we get a value of the desired format (i.e. printable english).