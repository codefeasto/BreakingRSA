## ECCRSA (TU Delft CTF 2024)
A custom cryptosystem is implemented. It attempts to combine RSA and Elliptic Curve Cryptography. We notice that the only difference from a standard RSA encryption is that we are given the sum of 2 points with x cordinates $p$ and  $q$. 



$\ell = \frac{y_2 - y_1}{x_2 - x_1}$ is the slope *

And thus we have the following equations: 

$n = p \cdot q$  
$S_x = \ell^2 - p - q$  
$S_y = \ell \cdot (p - S_x) - y_p$  

At this point I was 90% convinced that the system was well-constrained, expanding all equations I was pleased to find that this was indeed the case. 

We can use some very common linear algebra tricks, namely solving the system using a Groebner basis, and then reducing it by applying consecutive resultants to be left out with only 1 equation.

For reference, these are the 5 equations that we can deduce from the data:

$p_1 = y_p^2 - (x_p^3 + a \cdot x_p + b)$

$p_2 = y_q^2 - (x_q^3 + a \cdot x_q + b)$

$pol_1 = (y_q - y_p)^2 - x_p \cdot (x_q - x_p)^2 - x_q \cdot (x_q - x_p)^2 - S_x \cdot (x_q - x_p)^2$

$pol_2 = (y_q - y_p) \cdot (x_p - S_x) - y_p \cdot (x_q - x_p) - S_y \cdot (x_q - x_p)$

$pol_3 = N - x_p \cdot x_q$
