from Crypto.Util.number import getPrime, isPrime
import os


def getPp1(x, k):
    while True:
        a = 4
        for _ in range(k):
            a *= getPrime(x // k)
        p = a - 1
        if isPrime(p):
            return p


p, q = getPp1(512, 16), getPp1(512, 16)
flag = os.environ.get(
    "FLAG", "FLAG{CaTcH_Th3_Fl4g_If_Y0u_C4n_Th3_Fl4g_1s_0n_Th3_W4y_Or_N0t_!!}"
).encode()