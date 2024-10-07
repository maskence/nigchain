from dataclasses import dataclass, asdict
import base64
from concurrent.futures import ThreadPoolExecutor
import requests
import ecdsa
from hashlib import sha256
import logging 

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def abreviate(string, max_len = 10):
    if len(string) <= max_len:
        return string
    new_str = string[:max_len//2] + '...' + string[-max_len//2:]
    return new_str

@dataclass
class Tx():
    sender : str
    receiver : str
    amount : float
    signature : str

    def to_string(self):
        return self.sender+self.receiver+str(self.amount)+self.signature
    def __repr__(self):

        return f"Tx(sender='{abreviate(self.sender)}', receiver={abreviate(self.receiver)}, amount={self.amount}, signature='{abreviate(self.signature)}')"
@dataclass
class Block():
    txs : list
    previous_block_hash : str
    nonce : int
    height : int

    def to_string(self):
        return f"{'|'.join(tx.to_string() for tx in self.txs)}|{self.previous_block_hash}|{self.height}|{self.nonce}"


class Wallet():
    public_key : str
    private_key : str
    incoming_txs : list
    outgoing_txs : list
    peers = []
    def __init__(self, peers = None):
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha256)
        self.private_key_str = self.private_key.to_string().hex()

        self.public_key = self.private_key.get_verifying_key()
        self.public_key_str = self.public_key.to_string().hex()

        self.incoming_txs, self.outgoing_txs = [], []

        self.peers = peers if peers is not None else []

    def get_balance(self):
        return sum(tx.amout for tx in incoming_txs) - sum(tx.amout for tx in outgoing_txs)
    def generate_tx(self, payee, amount, dummy=False):
        tx_data = self.public_key_str + payee + str(amount)
        signature = self.private_key.sign((tx_data).encode()).hex()
        tx = Tx(self.public_key_str, payee, amount, signature)
        return tx
    def publish_tx(self, tx : Tx):
        if not self.peers:
            logging.warning('Warning, not peers to broadcast transaction to : aborting transaction')
            return

        published_to_n_peers = 0
        with ThreadPoolExecutor() as exe:
            for resp, url in exe.map(lambda url : make_request(requests.Request('POST',url+'/receive_tx', json=asdict(tx))), self.peers):
                if resp is None:
                    logging.info(f'transaction {tx} not published to {url} : host did not respond')
                else:
                    logging.info(f'Transaction {tx} published to peer {url} succesfully')
                    published_to_n_peers += 1
        if published_to_n_peers == 0 :
            logging.warning(f'Transaction {tx} could not be published to any peers, aborting')
            return
        self.outgoing_txs.append(tx)
        
    def send(self, payee, amout):
        tx = self.generate_tx(payee=payee, amount=amout)
        self.publish_tx(tx)
        return tx

def make_request( req : requests.Request):
    sess = requests.Session()
    req = req.prepare()
    try :
        resp = sess.send(req)
    except requests.ConnectionError as e:
        return None, req.url
    return resp, req.url
    