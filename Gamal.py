import Crypto.Util.number as num
import random

"""
ElGamal Digital Signature Scheme
--------------------------------
Key Generation
--------------
1. Select a large random prime p and a generator α of Z∗p.
2. Generate a random integer x such that 1≤x≤p−2. 
3. Compute y = α**x mod p.
4. A’s public key is (p, α, y).
5. A’s private key is x.

Signature Generation
--------------------
A generates a signature for a message m (0 ≤ m < p−1) as follows:
1. Generatea random integer k such that 1≤k≤p−2 and gcd(k,p−1)=1.
2. Compute r = α**k mod p.
3. Compute k**−1 mod (p − 1).
4. Computes=k**−1(m−xr)mod(p−1). 
5. A’s signature for m is the pair (r, s),

Signature Verification
----------------------
A signature (r, s) produced by A can be verified as follows:
1. Verify that 1 ≤ r ≤ (p−1); if not return False.
2. Compute v1 = (y**r)(r**s) mod p. 
3. Compute v2 = α**m mod p. 
4. Return v1 = v2.
"""

sys_param_p = 1439  # Global system parameter p.
sys_param_a = 1343  # Global system parameter a.

# returns (p,a) containing a safe prime p with s bits and a generator a for Z∗p.
def pair(s):
    safe_prime = 0
    while (True):
        p = num.getPrime(s)
        safe_prime = 2 * p + 1
        if (num.isPrime(safe_prime)):
            break
    while (True):
        a = random.randint(2, safe_prime - 1)
        if ((safe_prime - 1) % a != 1):
            break

    return safe_prime, a


# Key Generation
def generateElGamalKey():
    # p, a = pair(s)
    z = random.randint(1, sys_param_p - 2)
    b = pow(sys_param_a, z, sys_param_p)
    return z, b


# Signature Generation
def generateElGamalSignature(z, msg):
    while 1:
        k = random.randint(1, sys_param_p - 2)
        if num.GCD(k, sys_param_p - 1) == 1:
            break
    r = pow(sys_param_a, k, sys_param_p)
    l = num.inverse(k, sys_param_p - 1)

    s = ",".join([str(l * (ord(m) - z * r) % (sys_param_p - 1)) for m in msg])
    return r, s


# Signature Verification
def verifyElGamalSignature(b, r, s, m):
    if r < 1 or r > sys_param_p - 1:
        return False

    s = s.split(",")
    s = [int(c) for c in s]  # Get splitted string back to int array.

    m = [ord(c) for c in m]  # Convert message to array of int.

    if len(m) != len(s):
        return False
    valid = True
    for indx, c in enumerate(m):
        v1 = pow(b, r, sys_param_p) % sys_param_p * pow(r, s[indx], sys_param_p) % sys_param_p
        v2 = pow(sys_param_a, m[indx], sys_param_p)

        if v1 != v2:
            valid = False
    return valid



# if __name__ == "__main__":
#     message = "get dfdsf it"
#     print("Message: ", message)
#
#     sig_priv_key, sig_pub_key = generateElGamalKey(10)
#     print("sys_param_p, sys_param_a, sig_priv_key, sig_pub_key", sys_param_p, sys_param_a, sig_priv_key, sig_pub_key)
#     rr, ss = generateElGamalSignature( sig_priv_key, message)  # signature.
#     print("rr, ss", rr, ss)
#     isValid = verifyElGamalSignature(sig_pub_key, rr, ss, message)
#     print("Valid Signature: ", isValid)
