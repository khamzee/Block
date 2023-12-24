from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from datetime import datetime

# Шаг 1: Асимметричное шифрование
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Шаг 2: Цифровая подпись
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# Шаг 3: Blockchain Application Development
class Transaction:
    def init(self, sender, recipient, amount):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = datetime.now()

class Block:
    def init(self, previous_hash=''):
        self.transactions = []
        self.previous_hash = previous_hash
        self.timestamp = datetime.now()
        self.nonce = 0
        self.hash = self.calculate_hash()

    def add_transaction(self, transaction, public_key_sender, private_key):
        signature = sign_message(private_key, f"{transaction.sender}{transaction.recipient}{transaction.amount}")
        self.transactions.append({
            'transaction': transaction,
            'signature': signature.hex()
        })

    def calculate_hash(self):
        data = f"{self.previous_hash}{self.transactions}{self.timestamp}{self.nonce}"
        return hash_data(data).hex()

    def mine_block(self, difficulty):
        prefix = '0' * difficulty
        while self.hash[:difficulty] != prefix:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Block Mined: {self.hash}")

class Blockchain:
    def init(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 2

    def create_genesis_block(self):
        return Block()

    def get_last_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_last_block().hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)

# Шаг 4: Hashing
def hash_data(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode())
    return digest.finalize()

# Шаг 5: Proof of Work
def main():
    blockchain = Blockchain()
    sender = input("Enter sender's name: ")
    recipient = input("Enter recipient's name: ")
    amount = float(input("Enter transaction amount: "))
    transaction = Transaction(sender, recipient, amount)
    private_key_sender, public_key_sender = generate_key_pair()
    block = Block()
    block.add_transaction(transaction, public_key_sender, private_key_sender)
    blockchain.add_block(block)
    
if __name__ == "__main__":
    main()
