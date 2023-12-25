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
            mgf=padding.MGF1(algorithm=utils.Prehashed(hashes.SHA256())),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=utils.Prehashed(hashes.SHA256())),
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
    def __init__(self, sender, recipient, amount):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = datetime.now()

class Block:
    def __init__(self, previous_hash=''):
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
    def calculate_merkle_root(self):
        transactions = [transaction['transaction'] for transaction in self.transactions if 'transaction' in transaction]
        if not transactions:
            return hash_data('').hex()

        new_transactions = transactions  # Используем переменную new_transactions

        while len(new_transactions) > 1:
            temp_transactions = []
            for i in range(0, len(new_transactions)-1, 2):
                data = f"{new_transactions[i]}{new_transactions[i+1]}"
                temp_transactions.append(hash_data(data).hex())
            
            if len(new_transactions) % 2 == 1:
                data = f"{new_transactions[-1]}{new_transactions[-1]}"
                temp_transactions.append(hash_data(data).hex())

            new_transactions = temp_transactions

        return new_transactions[0]
    
    def mine_block(self, difficulty):
        prefix = '0' * difficulty
        while self.hash[:difficulty] != prefix:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Block Mined: {self.hash}")

class Blockchain:
    def __init__(self):
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

    def get_balance(self, account_name):
        balance = 0
        for block in self.chain:
            for transaction_data in block.transactions:
                if 'transaction' in transaction_data:  # Изменим проверку наличия ключа 'transaction'
                    transaction = transaction_data['transaction']
                    if isinstance(transaction, Transaction):
                        if transaction.sender == account_name:
                            balance -= transaction.amount
                        if transaction.recipient == account_name:
                            balance += transaction.amount
        return balance

    def transaction_history(self, account_name):
        history = []
        for block in self.chain:
            for transaction_data in block.transactions:
                if 'transaction' in transaction_data:
                    transaction = transaction_data['transaction']
                    if isinstance(transaction, Transaction):
                        if transaction.sender == account_name or transaction.recipient == account_name:
                            history.append(transaction)
        return history


# Дополнительная функциональность
def hash_data(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode())
    return digest.finalize()

# Расширенный пользовательский интерфейс
def user_interface():
    blockchain = Blockchain()

    while True:
        print("\nOptions:")
        print("1. Add a transaction")
        print("2. Check balance")
        print("3. Transaction history")
        print("4. Display blockchain")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            sender = input("Enter sender's name: ")
            recipient = input("Enter recipient's name: ")
            amount = float(input("Enter transaction amount: "))
            transaction = Transaction(sender, recipient, amount)
            private_key_sender, public_key_sender = generate_key_pair()
            new_block = Block()
            new_block.add_transaction(transaction, public_key_sender, private_key_sender)
            merkle_root = new_block.calculate_merkle_root()
            if new_block.transactions and new_block.transactions[-1].get('merkle_root'):
                print(f"Merkle Root: {new_block.transactions[-1]['merkle_root']}")
            else:
                print("No transactions or merkle root in the block.")
            new_block.mine_block(blockchain.difficulty)
            merkle_root = new_block.calculate_merkle_root()
            new_block.transactions.append({
                'merkle_root': merkle_root
            })
            blockchain.add_block(new_block)
            print("Transaction added successfully!")

        elif choice == '2':
            account_name = input("Enter account name: ")
            balance = blockchain.get_balance(account_name)
            print(f"Balance for {account_name}: {balance}")

        elif choice == '3':
            account_name = input("Enter account name: ")
            history = blockchain.transaction_history(account_name)
            print(f"Transaction history for {account_name}:")
            for transaction in history:
                print(f"{transaction.sender} -> {transaction.recipient}: {transaction.amount}")

        elif choice == '4':
            print("\nBlockchain:")
            for i, block in enumerate(blockchain.chain):
                print(f"\nBlock {i+1}:")
                print(f"Block Hash: {block.hash}")
                print(f"Previous Hash: {block.previous_hash}")
                if block.transactions:
                    print(f"Merkle Root: {block.transactions[-1].get('merkl1e_root', 'No merkle root in the block')}")
                    print(f"Transactions: {block.transactions[:-1]}")
                else:
                    print("No transactions in the block.")
                print(f"Timestamp: {block.timestamp}")
            print("----------------------------")

        elif choice == '5':
            print("Exiting the blockchain application. Goodbye!")
            break

        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    user_interface()
