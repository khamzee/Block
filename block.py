from datetime import datetime
import hashlib
import random

# Step 1: Asymmetric Encryption
class KeyPair:
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

def generate_key_pair():
    # Implement key pair generation (replace this with your own implementation)
    public_key = random.randint(2, 100)
    private_key = random.randint(101, 200)
    return KeyPair(public_key, private_key)

# Step 2: Digital Signature
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

    def add_transaction(self, transaction, private_key):
        signature = sign_message(private_key, f"{transaction.sender}{transaction.recipient}{transaction.amount}")
        self.transactions.append({
            'transaction': transaction,
            'signature': signature
        })

    def calculate_hash(self):
        data = f"{self.previous_hash}{self.transactions}{self.timestamp}{self.nonce}"
        return hash_data(data)

    def calculate_merkle_root(self):
        transactions = [transaction['transaction'] for transaction in self.transactions if 'transaction' in transaction]
        if not transactions:
            return hash_data('')

        new_transactions = transactions

        while len(new_transactions) > 1:
            temp_transactions = []
            for i in range(0, len(new_transactions)-1, 2):
                data = f"{new_transactions[i]}{new_transactions[i+1]}"
                temp_transactions.append(hash_data(data))

            if len(new_transactions) % 2 == 1:
                data = f"{new_transactions[-1]}{new_transactions[-1]}"
                temp_transactions.append(hash_data(data))

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

# Step 3: Hashing
def hash_data(data):
    return hashlib.sha256(str(data).encode()).hexdigest()

def sign_message(private_key, message):
    return pow(int(hash_data(message), 16), private_key.private_key, private_key.public_key)

def user_interface():
    blockchain = Blockchain()

    while True:
        print("\nOptions:")
        print("1. Add a transaction")
        print("2. Display blockchain")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            sender = input("Enter sender's name: ")
            recipient = input("Enter recipient's name: ")
            amount = float(input("Enter transaction amount: "))
            transaction = Transaction(sender, recipient, amount)
            key_pair = generate_key_pair()
            new_block = Block()
            new_block.add_transaction(transaction, key_pair)
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
            print("\nBlockchain:")
            for i, block in enumerate(blockchain.chain):
                print(f"\nBlock {i+1}:")
                print(f"Block Hash: {block.hash}")
                print(f"Previous Hash: {block.previous_hash}")
                if block.transactions:
                    print(f"Merkle Root: {block.transactions[-1].get('merkle_root', 'No merkle root in the block')}")
                    print(f"Transactions: {block.transactions[:-1]}")
                else:
                    print("No transactions in the block.")
                print(f"Timestamp: {block.timestamp}")
            print("----------------------------")

        elif choice == '3':
            print("Exiting the blockchain application. Goodbye!")
            break

        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    user_interface()
