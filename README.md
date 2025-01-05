
This repository contains implementations of the attacks described in Dan Boneh's paper, [Twenty Years of Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf), along with a collection of interesting RSA problems that I have gathered over the years through contests and learning sessions. 


The primary language of choice is python, with a SageMath 10.2 kernel.


When I first started this project in late 2023, my goal was to gain a deeper understanding of the RSA cryptosystem, and explore some of the cases that compromise security (even though I follow through with their respective proofs). Although fascinating, provable security, is out of the scope of this project. Instead, my focus was on developing a practical understanding of RSA and becoming familiar with SageMath for cybersecurity Capture The Flag (CTF) competitions. For this reason, I have implemented various fundamental algorithms from their mathematical outline which are already present in the SageMath API. 

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
8. QRSA (Grey Cat The Flag 2023)
