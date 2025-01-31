## krsa (Intigriti CTF 2024)

This is a textbook RSA-2048 implementation with no twists.


This challenge simply requires to decrypt a ciphertext corresponding to a random 32-bit plaintext encrypted with a textbook RSA-2048 instance. While normally this would be bruteforcable, a tight timeout is enforced that prohibits exhaustive enumeration of all 32-bit messages that could possible produce the given ciphertext. In order to bypass this constraint, the solution is to employ a Meet-in-the-Middle approach, which decreases the amount of bruteforce needed from 2^32 to ~2^17 bits, a singificant optimation that makes the attack run in < 1a. The catch is that in order to carry out the MitM attack, the message needs to be able to be expressed as the product of two 16-bit numbers . While this is not guaranteed to be always the case, it occurs with highenough probability that simply resetting the server connection and making a new attempt is guaranteed to succeed within a few tries. 