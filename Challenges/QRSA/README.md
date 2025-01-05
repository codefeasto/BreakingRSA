## QRSA (Grey Cat The Flag 2023)

This challenge implements RSA in Q[√41]. After some searching we can find this paper, https://www.diva-portal.org/smash/get/diva2:1170568/FULLTEXT01.pdf which explains that if the norm of N can be factorized, then we can recover phi, and effectively recover the message (indeed, our N is very smooth). The catch is that phi is not calculated like Z because the structure of the group differs. But, we can follow 5.2 to calculate phi.

note that Q[√41] is a UFD.

So Q[d]/x = Q[d]/(y1^a1) * ... * Q[d]/(yn^an)

If y is in Z then norm(y) = p^2 with p being prime.

ord(Q[d]/(y^a)) = (p^2 - 1) * p^2(a-1)

Else if y is not in Z then norm(y) is prime.

ord(Q[d]/(y^a)) = (p - 1) * p^(a-1)

and since norm is multiplicative:

Norm(x) = norm(y1)^a1 * ... * Norm(y2)^a2
