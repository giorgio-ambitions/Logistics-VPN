import hashlib
import os

# ==========================================
# 1. Number Theory Foundation: Diffie-Hellman
# ==========================================
# In a real VPN, these numbers are massive (e.g., 2048-bit primes).
# For this educational example, we use a smaller prime (p) and generator (g).
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1  # A large prime (truncated for demo)
# Let's use a standard small prime for guaranteed fast modular arithmetic in this script:
PRIME = 23  
GENERATOR = 5   # A primitive root modulo 23

def generate_keypair():
    """Generates a private key and a public key using modular exponentiation."""
    # Pick a random private key (in reality, a cryptographically secure random integer)
    private_key = int.from_bytes(os.urandom(2), 'big') % PRIME
    
    # Public key = (Generator ^ private_key) % PRIME
    # This uses Python's built-in modular exponentiation: pow(base, exp, mod)
    public_key = pow(GENERATOR, private_key, PRIME)
    
    return private_key, public_key

# ==========================================
# 2. Simulating the Handshake
# ==========================================
print("--- 1. KEY EXCHANGE PHASE ---")

# Alice's side
alice_private, alice_public = generate_keypair()
print(f"Alice's Public Key sent over network: {alice_public}")

# Bob's side
bob_private, bob_public = generate_keypair()
print(f"Bob's Public Key sent over network:   {bob_public}")

# Both sides compute the Shared Secret using number theory:
# Alice computes: (Bob's Public Key) ^ Alice's Private Key % PRIME
alice_shared_secret = pow(bob_public, alice_private, PRIME)

# Bob computes: (Alice's Public Key) ^ Bob's Private Key % PRIME
bob_shared_secret = pow(alice_public, bob_private, PRIME)

print(f"\nAlice's computed secret: {alice_shared_secret}")
print(f"Bob's computed secret:   {bob_shared_secret}")
assert alice_shared_secret == bob_shared_secret, "Secrets match!"
print(">>> Shared secret successfully established securely over an untrusted channel! <<<\n")


# ==========================================
# 3. Encrypting a VPN "Packet"
# ==========================================
print("--- 2. SECURE TUNnel PHASE ---")

# Convert the mathematical shared secret into a fixed-size cryptographic key using a hash function (SHA-256)
encryption_key = hashlib.sha256(str(alice_shared_secret).encode()).digest()

def simple_xor_encrypt(message: bytes, key: bytes) -> bytes:
    """A toy symmetric cipher (XOR cipher) to demonstrate data protection using the derived key."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(message)])

# Original packet payload (e.g., web traffic passing through the VPN tunnel)
original_packet = b"GET /confidential-data HTTP/1.1"
print(f"Original Packet: {original_packet.decode()}")

# Encrypt the packet
encrypted_packet = simple_xor_encrypt(original_packet, encryption_key)
print(f"Encrypted Packet (what an eavesdropper sees): {encrypted_packet}")

# Decrypt the packet on the receiving end using the same shared key
decrypted_packet = simple_xor_encrypt(encrypted_packet, encryption_key)
print(f"Decrypted Packet: {decrypted_packet.decode()}")
