from sage.all_cmdline import *
from Crypto.Util.number import getPrime, isPrime

def genCurve(bitsize, smooth):
  while True:
    try:
      # Generates num_factors primes and multiplies them together to form a modulus 
      order = 1

      # Currently the best way I can think of to generate primes p such that p - 1 is B-smooth
      while not is_prime(order) and order.bit_length() != bitsize:
        order = 2 * prod([getPrime(smooth) for i in range(bitsize // smooth)]) 
        order *= getPrime(bitsize - order.bit_length())
        order += 1

      p = next_prime(order+getPrime(32))
      F = GF(p)

      # Step 2: Desired prime order n
      n = order

      # Step 3: Compute the trace of Frobenius t
      t = p + 1 - n

      # Step 4: Check Hasse's theorem
      assert abs(t) <= 2*sqrt(p), "Trace does not satisfy Hasse's theorem"

      # Step 5: Discriminant D
      D = t^2 - 4*p
      print(D % 4)
      # Step 6: Compute the Hilbert class polynomial H_D(x)
      H = hilbert_class_polynomial(D)
      print(H)
      # Step 7: Find roots of H_D(x) modulo p
      j_invariant = H.roots(F)[0][0]

      # Step 8: Construct the elliptic curve from the j-invariant
      E = EllipticCurve_from_j(j_invariant)

      # Step 9: Verify the order
      assert E.order() == n, "Elliptic curve order does not match the desired prime order"
      return E
    except Exception as e:
      print(e)
      continue
  
def main():
  E = genCurve(256, 16)
  print(E)
  print(E.order())

if __name__ == "__main__":
  main()