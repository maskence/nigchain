from lib import Wallet, Tx, Block

import threading
import requests
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
import pickle
from hashlib import sha256
from flask import Flask, request
import sys
import time
import json
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_public_key
import base64
import ecdsa

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def get_blockchain_height(host):
    try:
        resp = requests.get(host + '/get_blockchain_height')
    except requests.exceptions.ConnectionError as e:
        print(f'Error when requesting blockchain height : {host} did not answer')
        return host, -1

    if resp.status_code != 200 and not resp.json:
        return host, -1
    
    return host, resp.json()['height']

def get_blockchain(host,start : int, end : int):
    resp = requests.get( host + f'/get_blockchain?start={start}&end={end}')

    payload = resp.json()
    try:
        new_blocks = []
        for block_json in payload:
            block_json['txs'] = [Tx(**tx) for tx in block_json['txs']]
            new_blocks.append(Block(**block_json))
        return new_blocks
    except Exception as e:
        print('Error : json does not respect blockchain format')
        return None
    

def validate_transaction(tx):
    if tx.sender == 'coinbase':
        signature_valid = True
    else:
        public_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(tx.sender), curve=ecdsa.SECP256k1, hashfunc=sha256)
        try:
            signature_valid = public_key.verify(bytes.fromhex(tx.signature), (tx.sender+tx.receiver+str(tx.amount)).encode()) # True
        except ecdsa.BadSignatureError as e:
            return False
    #TODO check for double spend here
    return signature_valid

def validate_blockchain(blockchain : list, difficulty : int) -> bool:
    for i in range(1,len(blockchain)):
        previous_block, current_block = blockchain[i-1], blockchain[i]

        previous_block_hash = sha256(previous_block.to_string().encode()).hexdigest()
        if current_block.previous_block_hash != previous_block_hash:
            return False

        current_block_hash = sha256(current_block.to_string().encode()).hexdigest()
        if not bin(int(current_block_hash,16)).endswith('0' * difficulty):
            return False
        
        for tx in current_block.txs:
            if not validate_transaction(tx):
                return False
    return True

def send_block(block : Block, host : str):
        try:
            resp = requests.post(host + '/receive_new_block', json=asdict(block))
            if resp.status_code == 200:
                logging.info(f'Succesfully published block {block.height} to peer {host}')
            else:
                logging.warning(f'Host {host} has rejected our block {block.height}')
            return resp
        except requests.exceptions.ConnectionError:
            logging.debug(f'Error when publishing block : peer {host} did not answer')
            return None

def compute_nounce(block : Block, difficulty ):
    global blockchain_has_changed
    block_hash = '1'
    while True:
        if blockchain_has_changed:
            return None
        
        block_hash = sha256(block.to_string().encode()).hexdigest()
        if bin(int(block_hash, 16)).endswith('0' * difficulty):
            return block
        block.nonce += 1
        time.sleep(0.1)

#load blockchain and transaction tree
print('loading the current blockchain from disk ...')
with open('blockchain.pkl', 'rb') as f:
    blockchain = pickle.load(f)

genesis_block = Block([Tx('coinbase','satoshi',1, signature='')], previous_block_hash='', height=0, nonce=0)
if len(blockchain) == 0:
    blockchain.append(genesis_block)
transaction_tree = 'tkt'
awaiting_txs = []
blockchain_has_changed = False
difficulty = 4 

port = int(sys.argv[1]) if len(sys.argv) >= 2 else 9000
address = 'localhost'
peers = [f'http://localhost:{p}' for p in range(9000,9004) if p != port]
print(peers, port)
#..


app = Flask(__name__,)

@app.route('/get_blockchain_height')
def get_blockchain_height_route():
    return {'height': len(blockchain)}, 200

@app.route('/get_blockchain')
def get_blockchain_route():
    start, end = int(request.args['start']), int(request.args['end'])
    return blockchain[start : end+1], 200

@app.route('/receive_tx', methods=['POST'])
def receive_tx_route():
    global awaiting_txs

    payload = request.get_json()
    try:
        tx = Tx(**payload)
    except Exception as e:
        print('Error : json doesnt conform to the expected transaction structure')
        return ({},400)
    if validate_transaction(tx):
        awaiting_txs.append(tx)
        return ({}, 200)
    else:
        print(f'Transaction invalid {tx}')
        return ({'err': 'transaction invalid'}, 401)
    

@app.route('/receive_new_block', methods = ['POST'])
def receive_new_block_route():
    payload = request.get_json()
    try:
        payload['txs'] = [Tx(**tx) for tx in payload['txs']]
        new_block = Block(**payload)
    except Exception as e:
        print('Error : json doesnt conform to the expected block structure')
        return ({}, 400)
    valid = new_block.height == len(blockchain) and validate_blockchain([blockchain[-1],new_block], difficulty)
    if valid:
        global blockchain_has_changed
        blockchain.append(new_block)
        blockchain_has_changed = True
        
        logging.info(f'accepted new block from peer {request.host} of height {new_block.height}')
        with ThreadPoolExecutor() as exe:
            for host in peers:
                exe.submit(lambda h : send_block(new_block, h), host)
        return ({},200)
    else:
        print(f'rejected block from peer {request.url}:', new_block, 'current height', len(blockchain)-1, blockchain[-1])
        return ({},400)

##find if there is a longer blockchain among peers and sync it
with ThreadPoolExecutor() as exe:
    peers_blockchain_heights = list(exe.map(get_blockchain_height, peers))

peers_longer_blockchains = [x for x in peers_blockchain_heights if x[1] > len(blockchain)]
peers_longer_blockchains.sort(key = lambda x : x[1])

for host, height in peers_longer_blockchains:
    logging.info(f'founder longer blockchain of height {height} from {host}')
    new_blocks = get_blockchain(host, start=len(blockchain), end=height)

    test_chain = [blockchain[-1], *new_blocks] if len(blockchain) > 1 else new_blocks
    if new_blocks and validate_blockchain(test_chain, difficulty=difficulty):
        blockchain += new_blocks
        logging.info(f'successfully downloaded blockchain up to {height} from {host}')
        break
    else:
        logging.warning(f'blockchain downloaded from {host} invalid ', new_blocks)
#..

##Start server to publish and receive new blocks and transactions
server_thread = threading.Thread(target=lambda : app.run(host = 'localhost', port = port), daemon=True)
server_thread.start()
#..


##mine
my_wallet = Wallet() 
mining_start_time, start_blockchain_len = time.time(), len(blockchain)

while True:
    blockchain_has_changed = False
    mining_reward = Tx('coinbase', my_wallet.public_key_str, 1, signature='')
    previous_block_hash = sha256(blockchain[-1].to_string().encode()).hexdigest()
    block_to_mine = Block(txs = [ mining_reward,*awaiting_txs[:10]],
     nonce=0, height=len(blockchain), previous_block_hash=previous_block_hash )

    #if the blockchain changes this function is interrupted and returns None
    new_block = compute_nounce(block_to_mine, difficulty)

    if new_block is not None:
        blockchain.append(new_block)
        my_wallet.incoming_txs.append(mining_reward)
        logging.info(f'Found new block at height {new_block.height}')
        with ThreadPoolExecutor() as exe:
            publish_responses = list(exe.map(lambda h : send_block(new_block, h), peers))


    print(len(blockchain), 'Average new block time :' , (time.time() - mining_start_time) / (len(blockchain)-start_blockchain_len))

#.. 

