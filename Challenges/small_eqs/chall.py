from Crypto.Util.number import getPrime, isPrime, bytes_to_long


p=getPrime(512)
while True:
	w=getPrime(20)
	x=2*w*p-1
	if isPrime(x):
		break

q=getPrime(512*2)
n = p * q * x
e = 65537
m = bytes_to_long(b'redacted')
c = pow(m, e, n)
print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
print(w)

'''
n = 18186672849609603331344182584568642941078893104802301217241028624469607021717197485036251613075846729705028441094100248337306406098776983108141004863456595015660485098203867670995838502297993710897784135087115777697925848407153788837657722171924264421550564295047937036911411846582733847201015164634546149603743246378710225407507435371659148999942913405493417037116587298256802831009824832360479040621348157491754407277404391337488226402711686156101028879269050800874367763551119682177453648890492731413760738825931684979379268401715029193518612541590846238434595210876468090976194627398214837801868969047036272502669215123
e = 65537
c = 1617999293557620724157535537778741335004656286655134597579706838690566178453141895621909480622070931381931296468696585541046188947144084107698620486576573164517733264644244665803523581927226503313545336021669824656871624111167113668644971950653103830443634752480477923970518891620296211614968804248580381104245404606917784407446279304488720323993268637887493503760075542578433642707326246816504761740168067216112150231996966168374619580811013034502620645288021335483574561758204631096791789272910596432850424873592013042090724982779979496197239647019869960002253384162472401724931485470355288814804233134786749608640103461
'''
