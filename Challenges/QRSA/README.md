## QRSA (Grey Cat The Flag 2023)

This challenge implements RSA in $\mathbb{Q}[\sqrt{41}]$. After some searching we can find this paper, https://www.diva-portal.org/smash/get/diva2:1170568/FULLTEXT01.pdf which explains that if the norm of N can be factorized, then we can recover phi, and effectively recover the message (indeed, our N is very smooth). The catch is that phi is not calculated like Z because the structure of the group differs. But, we can follow 5.2 to calculate phi.

Note that $\mathbb{Q}[\sqrt{41}]$ is a UFD.

So, 

$\mathbb{Q}[d]/x = \mathbb{Q}[d]/y_1^{a_1} \cdot \mathbb{Q}[d]/y_2^{a_2} \cdots \mathbb{Q}[d]/y_n^{a_n}$

If $y \in \mathbb{Z}$, then $\text{Norm}(y) = p^2$ with $p$ being prime.

$\text{ord}(\mathbb{Q}[d]/y^a) = (p^2 - 1) \cdot p^{2(a-1)}$

If $y \notin \mathbb{Z}$, then $\text{Norm}(y)$ is prime.

$\text{ord}(\mathbb{Q}[d]/y^a) = (p - 1) \cdot p^{a-1}$

Since the norm is multiplicative:

$\text{Norm}(x) = \text{Norm}(y_1)^{a_1} \cdot \text{Norm}(y_2)^{a_2} \cdots \text{Norm}(y_n)^{a_n}$

