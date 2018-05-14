# -*- coding: utf-8 -*-
"""
Created on Wed May  2 15:05:12 2018

@author: Administrator
"""

from blockchain import Blockchain

import random
import string

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
import base64

import os
import glob

from flask import Flask, jsonify, request, send_file
import requests

# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = ''.join(random.choices(string.ascii_letters+string.digits, k=16))

# Instantiate the Blockchain
blockchain = Blockchain()

@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash, node_identifier)
    
    # We must receive a reward for finding the proof.
    blockchain.change_amount(node_identifier, block['fee'], "add")
    
    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'fee': block['fee'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'password', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    transaction_id = ''.join(random.choices(string.ascii_letters+string.digits, k=16))
    sender = values['sender']
    block = {
        'sender': values['sender'],
        'recipient': values['recipient'],
        'amount': values['amount'],
        'id': transaction_id,
        'transaction': 'Transaction'
    }
    try:
        key = RSA.import_key(open(f'{sender}-key.bin').read(), passphrase=values['password'])
    except:
        return 'Invalid password', 400
    h = SHA256.new(str(block).encode("utf-8"))
    signature = base64.b64encode(pss.new(key).sign(h))
    block = {
        'sender': values['sender'],
        'recipient': values['recipient'],
        'amount': values['amount'],
        'transaction': 'Transaction',
        'id': transaction_id,
        'sign': signature
    }
    # Create a new Transaction
    index = blockchain.new_transaction(block)
    
    response = {'message': f'Transaction will be added to Block {index} if it is valid'}
    
    return jsonify(response), 201

@app.route('/loan/newrequest', methods=['POST'])
def new_request():
    values = request.get_json()
    
    # Check that the required fields are in the POST'ed data
    required = ['requester', 'amount', 'start_date', 'end_date']
    if not all(k in values for k in required):
        return 'Missing values', 400
    
    loan_id = ''.join(random.choices(string.ascii_letters+string.digits, k=16))
    
    block = {
        'requester': values['requester'],
        'amount': values['amount'],
        'start_date': values['start_date'],
        'end_date': values['end_date'],
        'loan_id': loan_id,
        'transaction': 'Loan Request',
        'Proposals': []
    }
    
    # Create a new account
    blockchain.loan_requests.append(block)
    
    response = f'New request created {block}'
    
    return jsonify(response), 201

@app.route('/loan/addproposal', methods=['POST'])
def add_proposal():
    values = request.get_json()
    
    # Check that the required fields are in the POST'ed data
    required = ['loan_id', 'loaner', 'interest']
    if not all(k in values for k in required):
        return 'Missing values', 400
    
    proposal = {
        'loaner': values['loaner'],
        'interest': values['interest']
    }
    
    done = blockchain.add_proposal(values['loan_id'], proposal)
    
    if done:
        response = f'New proposal created {proposal}'
    else:
        response = 'Proposal could not be created'
        
    return jsonify(response), 201

@app.route('/loan/getrequests', methods=['GET'])
def get_requests():
    response = {
        'requests': blockchain.loan_requests,
        'requester': blockchain.accounts
    }
    
    return jsonify(response), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/accounts/myaccount', methods=['POST'])
def my_account():
    values = request.get_json()
    
    # Check that the required fields are in the POST'ed data
    if not('address' in values):
        return 'Missing values', 400

    # Create a new account
    account = blockchain.return_account(values['address'])

    response = {'account': account}
    
    return jsonify(response), 201

@app.route('/accounts/all', methods=['GET'])
def all_accounts(): 
    response = {
        'accounts': blockchain.accounts,
        'length': len(blockchain.accounts),
    }
    return jsonify(response), 200

@app.route('/accounts/register', methods=['POST'])
def register_account():
    values = request.get_json()
    
    # Check that the required fields are in the POST'ed data
    required = ['password', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    address = ''.join(random.choices(string.ascii_letters+string.digits, k=16))
    
    key = RSA.generate(1024)
    private_key = key.export_key(passphrase=values['password'])
    public_key = key.publickey().export_key()
        
    file_out = open(f'{address}-key.bin', 'wb')
    file_out.write(private_key)
    file_out.close()
    
    # Create a new Transaction
    response = blockchain.register_account(address, public_key, values['amount'])
    
    return jsonify(response), 201

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    node = values.get('node')
    if node is None:
        return "Error: Please supply a valid node", 400
    
    if node not in blockchain.nodes:
        blockchain.register_node(node)
        requests.post(url=f'{node}/nodes/register', json={'node': blockchain.my_node})

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/all', methods=['GET'])
def all_nodes():
    response = {
        'nodes': list(blockchain.nodes)
    }
    return jsonify(response), 200

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

@app.route('/downloadfile', methods=['POST'])
def download_files():
    values = request.get_json()
    
    path = os.path.dirname(os.path.realpath(__file__))
    file = os.path.join(path, values['file'])
    if file in glob.glob(file):
        return send_file(file, attachment_filename=values['file'])
    else:
        return 'File Not found', 400

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-o', '--host', default='127.0.0.1', type=str, help='host ip')
    args = parser.parse_args()
    port = args.port
    host = args.host
    
    key = RSA.generate(1024)
    private_key = key.export_key(passphrase='password')
    public_key = key.publickey().export_key()
        
    file_out = open(f'{node_identifier}-key.bin', 'wb')
    file_out.write(private_key)
    file_out.close()
        
    # Register node as an address
    blockchain.register_account(node_identifier, public_key, 0)
    
    blockchain.register_node(f'{host}:{port}')
    blockchain.my_node = f'{host}:{port}'
    app.run(host=host, port=port)