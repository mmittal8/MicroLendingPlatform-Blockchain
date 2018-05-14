# -*- coding: utf-8 -*-
"""
Created on Wed Apr 25 11:30:34 2018

@author: Manan Mittal
"""

import json
from time import time
from urllib.parse import urlparse

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
import base64

import requests

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.loan_requests = []
        self.chain = []
        self.nodes = set()
        self.accounts = []
        self.my_node = ''
        
        # Create the genesis block
        self.new_block(previous_hash='1', proof=100, node_identifier='0')
    
    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """
        
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')
    
    def register_account(self, address, public_key, amount):
        
        """
        Add a new account to the list of accounts
        :param address: Address of account same as recipient or sender
        :param amount: Current tokens in account
        """
        
        file_out = open(f'{address}-public.bin', 'wb')
        file_out.write(public_key)
        file_out.close()

        if self.return_account(address) == None:
            block = {
                'address': address,
                'amount': amount,
                'key': str(public_key),
                'transaction': 'New Account'
            }
            self.new_transaction(block)

            response = {'message': f'New Account will be created with address {address} when next block is mined'}
            return response
        else:
            index = self.return_account(address)
            response = {'message': f'Account with this address already exists at {index}'}
            return response
    
    def return_account(self, address):
        
        """
        Add a new account to the list of accounts
        :param address: Address of account same as recipient or sender
        :param amount: Current tokens in account
        """
        
        current_account = None
        
        for acc in self.accounts:
            if acc["address"] == address:
                current_account = acc
    
        return current_account
    
    def change_amount(self, address, amount, change):
        
        """
        Add a new account to the list of accounts
        :param transaction: transaction listing the change in amount required
        """
        
        for acc in self.accounts:
            if acc["address"] == address:
                if change == "add":
                    self.accounts.remove(acc)
                    acc["amount"] += amount
                    self.accounts.append(acc)
                    break
                elif change == "deduct":
                    self.accounts.remove(acc)
                    acc["amount"] -= amount
                    self.accounts.append(acc)
                    break
                
    
    def valid_chain(self, chain, node):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            #print(f'{last_block}')
            #print(f'{block}')
            #print("\n-----------\n")
            
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                print('Hash Invalid')
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], block['previous_hash']):
                print('Proof invalid')
                return False

            for transaction in block['transactions']:
                if transaction['transaction'] == 'Transaction':
                    transaction_id = transaction['id']
                    response = requests.post(url=f'http://{node}/downloadfile', json = {'file': f'{transaction_id}.bin'})
                    file_out = open(f'{transaction_id}.bin', 'wb')
                    file_out.write(response.content)
                    file_out.close
                    if not self.valid_signature(self.return_account(transaction["sender"]), transaction):
                        print(f'One of the transactions is not valid')
                        return False
                elif transaction['transaction'] == 'New Account':
                    address = transaction['address']
                    response = requests.post(url=f'http://{node}/downloadfile', json = {'file': f'{address}-public.bin'})
                    file_out = open(f'{address}-public.bin', 'wb')
                    file_out.write(response.content)
                    file_out.close
                    
            last_block = block
            current_index += 1
        
        print(f'Chain Validated')
        return True
    
    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        
        for node in neighbours.copy():
            
            if node != self.my_node:
                response = requests.get(url=f'http://{node}/nodes/all')
                
                if response.status_code == 200:
                    nodes = response.json()['nodes']
                    
                    for new_node in nodes:
                        
                        if new_node not in neighbours:
                            self.nodes.add(new_node)
                        
        neighbours = self.nodes
        new_chain = None
        
        # We're only looking for chains longer than ours
        max_length = len(self.chain)
        
        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            if node != self.my_node:
                response = requests.get(url=f'http://{node}/chain')
                print(response)
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']
                    # Check if the length is longer and the chain is valid
                    if length > max_length:
                        print(max_length)
                        if self.valid_chain(chain, node):
                            max_length = length
                            new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            index = 0
            while index < len(self.chain):
                if self.chain[index] != new_chain[index]:
                    block = self.chain[index]
                    for transaction in block['transactions']:
                        self.current_transactions.append(transaction)
                index += 1;
            self.chain = new_chain
            self.redo_accounts()
            return True
        
        return False
    
    def redo_accounts(self):
        
        self.accounts = []
        
        for blocks in self.chain:
            fee = 0
            transactions = blocks['transactions']
            
            for transaction in transactions:
                if transaction['transaction'] == "New Account":
                    self.accounts.append({
                        'address': transaction["address"],
                        'amount': transaction["amount"],
                        'key': transaction['key']
                    })
                elif transaction["transaction"] == "Transaction":
                    fee += transaction["amount"]*0.01
                    self.change_amount(transaction["sender"], transaction["amount"], "deduct")
                    self.change_amount(transaction["recipient"], transaction["amount"]*0.99, "add")
                    
            self.change_amount(blocks['created_by'], fee, 'add')
        
    def valid_signature(self, account, transaction):
#        transaction_id = transaction['id']
#        address = account['address']
#        signature = open(f'{transaction_id}.bin', 'rb').read()
#        key = RSA.import_key(open(f'{address}-public.bin').read())
#
#        if (transaction['sign'] == str(signature)) and (account['key'] == str(key.export_key())):
#            block = {
#                'sender': transaction['sender'],
#                'recipient': transaction['recipient'],
#                'amount': transaction['amount'],
#                'id': transaction['id'],
#                'transaction': 'Transaction'
#            }
#            h = SHA256.new(str(block).encode("utf-8"))
#            signature_dec = base64.b64decode(signature)
#            try:
#                pss.new(key).verify(h, signature_dec)
#                print('validated')
#                return True
#            except (ValueError, TypeError):
#                print('Not Validated')
#                return False
#        else:
#            return False
        return True
        
    def new_block(self, proof, previous_hash, node_identifier):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """
        fee = 0
        valid_transaction = []
        for transaction in self.current_transactions:
            if transaction["transaction"] == "New Account":
                final_transaction = {
                    'address': transaction["address"],
                    'key': transaction['key'],
                    'amount': transaction["amount"],
                    'loans_taken': 0,
                    'loans_repaid': 0,
                    'loan_amount_taken': 0,
                    'loan_amount_repaid': 0,
                    'current_loan': 0
                }
                self.accounts.append(final_transaction)
                valid_transaction.append(final_transaction)
            elif transaction["transaction"] == "Transaction":
                sender_account = self.return_account(transaction["sender"])
                recipient_account = self.return_account(transaction["recipient"])
                if (sender_account != None) & (recipient_account != None) & (sender_account["amount"] >= transaction["amount"]):
                    if self.valid_signature(sender_account, transaction):
                        fee += transaction["amount"]*0.01
                        valid_transaction.append(transaction)
                        self.change_amount(transaction["sender"], transaction["amount"], "deduct")
                        self.change_amount(transaction["recipient"], transaction["amount"]*0.99, "add")
                

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': valid_transaction,
            'fee': fee,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
            'created_by': node_identifier
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        
        return block

    def new_transaction(self, block):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        
        if block['transaction'] == 'Transaction':
            transaction_id = block['id']
            file_out = open(f'{transaction_id}.bin', 'wb')
            file_out.write(block['sign'])
            file_out.close()
            block['sign'] = str(block['sign'])
            
        self.current_transactions.append(block)
        index = self.last_block['index'] + 1
        return index
    
    def add_proposal(self, loan_id, proposal):
        return True
    
    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode('utf-8')
        hsh = SHA256.new(str(block_string).encode("utf-8")).hexdigest()
        return hsh

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p such that hash(pl) contains leading 4 zeroes
         - Where l is the previous block, and p is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode('utf-8')
        guess_hash = SHA256.new(guess).hexdigest()
        return guess_hash[:4] == "0000"

