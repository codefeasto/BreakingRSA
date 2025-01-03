
This repository contains implementations to the attacks described in Dan Boneh's infamous paper [Twenty Years of Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf), as well as some interesting RSA problems that I gathered over the years both in contests and learning sessions. 


The primary language of choice is python with a SageMath 10.2 kernel.


When first creating this project in late 2023, my goal was to get a better grasp of the RSA cryptosystem, as well as explore some of the cases that compromise security (even though I follow through with most proofs). Although fascinating, provable security, is out of the scope of this project, as I targeted to develop a practical understanding and get familiar with SageMath for cybersecurity Capture The Flag (CTF) competitions. That's why I have implemented a lot of fundamental algorithms myself based on their respective proofs, but are in fact present in the SageMath API. 

## Twenty Years of Attacks on the RSA Cryptosystem

1. Recovering $p,q$ having $d$
2. Blinding
3. Hastad's attack
4. Common modulus
5. Franklin-Reiter related message attack
6. Wiener's attack
7. Coppersmith's Attack (LLL) on a partially known message

## Some interesting RSA problems

1. ECCRSA (TU Delft CTF 2024)
2. krsa (Intigriti CTF 2024)
3. Redundancy (vsCTF 2023)
4. RSA se olous RSei (NTUAH4CK 3.0)
5. RSA-2024 (imaginaryCTF monthly - Round 42)
6. RSATogether (ECSC 2024)
7. small eqs (0xL4ugh 2024)
