from lib import Wallet
import time


peers = [f'http://localhost:{p}' for p in range(9000,9004)]

my_wallet = Wallet(peers=peers)
while True:
    tx = my_wallet.send('statoshi',1)
    print(tx)
    time.sleep(0.5)
