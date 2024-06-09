from sage.all_cmdline import *
from pwn import remote, process
from Crypto.Cipher import AES

def SmartAttack(P,Q,p):
	E = P.curve()
	Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

	P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
	for P_Qp in P_Qps:
		if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
			break

	Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
	for Q_Qp in Q_Qps:
		if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
			break

	p_times_P = p*P_Qp
	p_times_Q = p*Q_Qp

	x_P,y_P = p_times_P.xy()
	x_Q,y_Q = p_times_Q.xy()

	phi_P = -(x_P/y_P)
	phi_Q = -(x_Q/y_Q)
	k = phi_Q/phi_P
	return ZZ(k)

def unpad(data, block_size):
    return data[:-data[-1]]

def decrypt(key, filein, fileout):
    with open(filein, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_ECB)
    with open(fileout, 'wb') as f:
        f.write(unpad(cipher.decrypt(data),16))
    print(f"Decrypted file {filein} to file {fileout}")

if __name__ == '__main__':
	io = remote('localhost', 8007)
	# io = process(['python3', 'chall.py']) # local testing
	io.recvuntil('p = ')
	p = int(io.recvline().strip())
	io.recvuntil('a = ')
	a = int(io.recvline().strip())
	io.recvuntil('b = ')
	b = int(io.recvline().strip())
	io.recvuntil('P1: ')
	P = eval(io.recvline().strip())
	io.recvuntil('P2: ')
	Q = eval(io.recvline().strip())
	io.recvuntil('P2 = secret * P1\n')
	P = EllipticCurve(GF(p), [a, b])(P)
	Q = EllipticCurve(GF(p), [a, b])(Q)
	secret = SmartAttack(P,Q,p)

	print(io.recvuntil(b"What is the value of 'secret'?: \n"))
	io.sendline(str(secret))
	result = io.recvline().strip().decode()
	print(result)
	if result == 'Success!':
		decrypt(secret.to_bytes(32)[:16], 'encrypted.enc', 'decrypted.pdf')
	else:
		print('Failed!')
	io.close()
