#!/usr/bin/env python3
from trezorlib.transport import get_transport, get_debug_transport
from trezorlib.tools import  b58decode, btc_hash, normalize_nfc, parse_path
from trezorlib.client import TrezorClient
from trezorlib.debuglink import TrezorClientDebugLink
from trezorlib import (btc, messages, ui)
from decimal import Decimal
from dash_config import DashConfig
from dashd_api import DashdApi
import requests
import base64
import struct
import socket
from mnemonic import Mnemonic


_DASH_COIN = 100000000


def compactsize(val):
    n = int(val)
    r = b''

    if n < 253:
        r += n.to_bytes(1, "big")
        return r

    if n < 0x10000:
        r += b'/253'
        r += n.to_bytes(2, "big")
        return r

    r += b'/254'
    r += n.to_bytes(4, "big")
    return r


def unpack_hex(hex_data):
    r = b""
    data_bytes = bytes.fromhex(hex_data)
    for b in data_bytes:
        r += struct.pack('c', b.to_bytes(1, "big"))
    return r


def _rpc_to_input(vin):
    i = messages.TxInputType()
    if "coinbase" in vin:
        i.prev_hash = b"\0" * 32
        i.prev_index = 0xFFFFFFFF  # signed int -1
        i.script_sig = bytes.fromhex(vin["coinbase"])
        i.sequence = vin["sequence"]

    else:
        i.prev_hash = bytes.fromhex(vin["txid"])
        i.prev_index = vin["vout"]
        i.script_sig = bytes.fromhex(vin["scriptSig"]["hex"])
        i.sequence = vin["sequence"]

    return i


def _rpc_to_bin_output(vout):
    o = messages.TxOutputBinType()
    o.amount = int(Decimal(vout["value"]) * 100000000)
    o.script_pubkey = bytes.fromhex(vout["scriptPubKey"]["hex"])

    return o


def rpc_tx_to_msg_tx(data):
    t = messages.TransactionType()
    t.version = data["version"]
    t.lock_time = data.get("locktime")

    t.inputs = [_rpc_to_input(vin) for vin in data["vin"]]
    t.bin_outputs = [_rpc_to_bin_output(vout) for vout in data["vout"]]

    if 'extra_data' in data:
        t.extra_data = unpack_hex(data['extra_data'])
        t.extra_data_len = len(t.extra_data)

    return t


def dash_sign_tx(client, inputs, outputs, details=None, prev_txes=None, extra_payload = None):
    print("dash_sign_tx")
    # set up a transactions dict
    txes = {None: messages.TransactionType(inputs=inputs, outputs=outputs, extra_data=extra_payload,
                                           extra_data_len=0 if extra_payload is None else len(extra_payload))}
    # preload all relevant transactions ahead of time
    for inp in inputs:
        try:
            prev_tx = prev_txes[inp.prev_hash]
        except Exception as e:
            raise ValueError("Could not retrieve prev_tx") from e
        if not isinstance(prev_tx, messages.TransactionType):
            raise ValueError("Invalid value for prev_tx") from None
        txes[inp.prev_hash] = prev_tx

    if details is None:
        signtx = messages.SignTx()
    else:
        signtx = details

    signtx.coin_name = 'Dash Testnet'
    signtx.inputs_count = len(inputs)
    signtx.outputs_count = len(outputs)
    signtx.extra_data_len = 0 if extra_payload is None else len(extra_payload)

    res = client.call(signtx)

    # Prepare structure for signatures
    signatures = [None] * len(inputs)
    serialized_tx = b""

    def copy_tx_meta(tx):
        tx_copy = messages.TransactionType()
        tx_copy.CopyFrom(tx)
        # clear fields
        tx_copy.inputs_cnt = len(tx.inputs)
        tx_copy.inputs = []
        tx_copy.outputs_cnt = len(tx.bin_outputs or tx.outputs)
        tx_copy.outputs = []
        tx_copy.bin_outputs = []
        tx_copy.extra_data_len = tx.extra_data_len
        tx_copy.extra_data = None
        return tx_copy

    R = messages.RequestType
    while isinstance(res, messages.TxRequest):
        # If there's some part of signed transaction, let's add it
        if res.serialized:
            if res.serialized.serialized_tx:
                serialized_tx += res.serialized.serialized_tx

            if res.serialized.signature_index is not None:
                idx = res.serialized.signature_index
                sig = res.serialized.signature
                if signatures[idx] is not None:
                    raise ValueError("Signature for index %d already filled" % idx)
                signatures[idx] = sig

        if res.request_type == R.TXFINISHED:
            print("R.TXFINISHED")
            break

        # Device asked for one more information, let's process it.
        current_tx = txes[res.details.tx_hash]

        if res.request_type == R.TXMETA:
            print("R.TXMETA")
            msg = copy_tx_meta(current_tx)
            print(msg)
            res = client.call(messages.TxAck(tx=msg))

        elif res.request_type == R.TXINPUT:
            print("R.TXINPUT")
            msg = messages.TransactionType()
            msg.inputs = [current_tx.inputs[res.details.request_index]]
            res = client.call(messages.TxAck(tx=msg))

        elif res.request_type == R.TXOUTPUT:
            print("R.TXOUTPUT")
            msg = messages.TransactionType()
            if res.details.tx_hash:
                msg.bin_outputs = [current_tx.bin_outputs[res.details.request_index]]
            else:
                msg.outputs = [current_tx.outputs[res.details.request_index]]

            res = client.call(messages.TxAck(tx=msg))

        elif res.request_type == R.TXEXTRADATA:
            print("R.TXEXTRADATA")
            o, l = res.details.extra_data_offset, res.details.extra_data_len
            msg = messages.TransactionType()
            msg.extra_data = current_tx.extra_data[o: o + l]
            res = client.call(messages.TxAck(tx=msg))

    if isinstance(res, messages.Failure):
        raise RuntimeError("Signing failed")

    if not isinstance(res, messages.TxRequest):
        raise RuntimeError("Unexpected message")

    if None in signatures:
        raise RuntimeError("Some signatures are missing!")

    return signatures, serialized_tx


def keyid_from_address(address):
    data = b58decode(address, None)
    return data[1:21].hex()


def serialize_payee_script(keyid):
    # standard pay-to-pubkeyhash script,
    # OP_DUP OP_HASH160 <PubkeyHash> OP_EQUALVERIFY OP_CHECKSIG,
    # constant length 25 byte
    r = b'\x19'  # = 25, script length
    r += struct.pack("c", b'\x76')  # OP_DUP
    r += struct.pack("c", b'\xa9')  # OP_HASH160
    r += struct.pack("c", b'\x14')  # keyid length
    r += unpack_hex(keyid)
    r += struct.pack("c", b'\x88')  # OP_EQUALVERIFY
    r += struct.pack("c", b'\xac')  # OP_CHECKSIG
    return r


def reverse_bytes(bytes_data):
    res = bytearray(bytes_data)
    res.reverse()
    return bytes(res)


def dash_proregtx_payload(collateral_out,  address, port, ownerKeyId,
                          operatorKey, votingKeyId, payeeKeyId, operatorReward,
                          inputsHash):
    r = b""
    r += struct.pack("<H", 1)  # version
    r += struct.pack('<H', 0)  # masternode type
    r += struct.pack('<H', 0)  # masternode mode
    # collateral txid
    for i in range(0, 32):
        r += struct.pack("c", b'\x00')
    r += struct.pack('<I', collateral_out)  # collateral out
    # ip address
    if not address == "0.0.0.0":
        r += socket.inet_aton(address)
    else:
        r += struct.pack('<Q', 0)
        r += struct.pack('<Q', 0)
    r += struct.pack(">H", port)  # port
    r += unpack_hex(ownerKeyId)  # owner keyid
    r += unpack_hex(operatorKey)  # operator key
    r += unpack_hex(votingKeyId)  # voting keyid
    r += struct.pack("<H", operatorReward) # operator reward
    r += serialize_payee_script(payeeKeyId)# payout script
    r += inputsHash  # inputs hash
    r += struct.pack("c", b'\x00')  # payload signature
    print("payload: ", r.hex())
    size = len(r)
    buf = int(size).to_bytes(1, "big")
    buf += r
    return buf


class HashWriter:
    def __init__(self):
        self.data = b''

    def add_data(self, data):
        print("Hash data:", data.hex())
        self.data += data

    def get_hash(self):
        return btc_hash(self.data)


class InsightApi:
    def __init__(self, url):
        self.url = url

    def _fetch_json(self, *path, **params):
        url = self.url + "/".join(map(str, path))
        return requests.get(url, params=params).json(parse_float=Decimal)

    def get_tx(self, txhash):
        data = self._fetch_json("tx", txhash)
        return rpc_tx_to_msg_tx(data)

    def get_addr_balance(self, address):
        return self._fetch_json("addr", address)["balance"]

    def get_addr_utxo(self, address):
        return self._fetch_json("addr", address, "utxo")


class LocalInfoApi:
    def __init__(self, dashd):
        self.dashd = dashd

    def get_tx(self, txhash):
        rawtx = self.dashd.rpc_command('getrawtransaction', txhash)
        txstruct = self.dashd.rpc_command("decoderawtransaction", rawtx)
        print(txstruct)
        if 'extraPayloadSize' in txstruct:
            txstruct['extra_data'] = compactsize(txstruct['extraPayloadSize']).hex() + txstruct['extraPayload']
        version = int(txstruct['version'])
        type = int(txstruct['type'])
        txstruct['version'] = version | (type << 16)
        print(txstruct)
        return rpc_tx_to_msg_tx(txstruct)

    def get_addr_balance(self, address):
        data = {"addresses": [address]}
        return self.dashd.rpc_command('getaddressbalance', data)["balance"] / _DASH_COIN

    def get_addr_utxo(self, address):
        data = {"addresses": [address]}
        res = self.dashd.rpc_command('getaddressutxos', data)
        # fix field set to useas insight api output
        for utxo in res:
            utxo['vout'] = utxo['outputIndex']
            utxo['amount'] = utxo['satoshis'] / _DASH_COIN
        return res


class DashTrezor:
    def __init__(self, client, api, seed):
        DashTrezor.load_device(client, seed)
        self.client = client
        # Get the first address of first BIP44 account
        # (should be the same address as shown in wallet.trezor.io)
        self.bip32_path = parse_path("44'/1'/0'/0/0")
        self.address = self.client.get_address('Dash Testnet', self.bip32_path)
        path = parse_path("44'/1'/0'/0/0/0")
        self.collateral_address = self.client.get_address('Dash Testnet', path)
        path = parse_path("44'/1'/0'/0/0/0/0")
        self.owner_address = self.client.get_address('Dash Testnet', path)
        self.api = api

    @classmethod
    def load_device(cls, client, seed_mnemonic):
        m = Mnemonic.normalize_string(seed_mnemonic)
        client.call(
            messages.LoadDevice(
                mnemonic=m,
                pin=None,
                passphrase_protection=False,
                language="english",
                label="test",
                skip_checksum=True,
            )
        )
        client.init_device()

    @classmethod
    def wipe_device(cls, client):
        client.call(messages.WipeDevice())

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        DashTrezor.wipe_device(self.client)

    def trezor_balance(self, address=None):
        if address is None:
            address = self.address
        return self.api.get_addr_balance(address)

    def send_to_address(self, address, amount):
        # prepare inputs
        txes = {}
        inputs = []
        trezor_address_data = self.api.get_addr_utxo(self.address)
        in_amount = Decimal(0.0)
        fee = Decimal(0.0)
        for utxo in trezor_address_data:
            if in_amount >= Decimal(amount) + fee:
                break
            fee = fee + Decimal(0.00001)
            new_input = messages.TxInputType(
                address_n=self.bip32_path,
                prev_hash=bytes.fromhex(utxo['txid']),
                prev_index=int(utxo['vout']),
                amount=int(Decimal(utxo['amount']) * _DASH_COIN),
                script_type=messages.InputScriptType.SPENDADDRESS,
                sequence=0xFFFFFFFF,
            )
            in_amount += Decimal(utxo['amount'])
            inputs.append(new_input)
            txes[bytes.fromhex(utxo['txid'])] = self.api.get_tx(utxo['txid'])

        # prepare outputs
        outputs = []
        new_output = messages.TxOutputType(
            address_n=None,
            address=address,
            amount=int(amount * _DASH_COIN),
            script_type=messages.OutputScriptType.PAYTOADDRESS
        )
        outputs.append(new_output)
        change = int((in_amount - fee) * _DASH_COIN) - int(amount * _DASH_COIN)
        if change > 1000:
            change_output = messages.TxOutputType(
                address_n=self.bip32_path,
                address=None,
                amount=change,
                script_type=messages.OutputScriptType.PAYTOADDRESS
            )
            outputs.append(change_output)

        # transaction details
        signtx = messages.SignTx()
        signtx.version = 2
        signtx.lock_time = 0

        # sign transaction
        _, signed_tx = dash_sign_tx(
            self.client, inputs, outputs, details=signtx, prev_txes=txes
        )

        return signed_tx

    def get_collateral(self):
        data = self.api.get_addr_utxo(self.collateral_address)
        for utxo in data:
            if Decimal(utxo['amount']) == Decimal(1000.0):
                return True, utxo['txid'], utxo['vout']
        return False, None, None

    def register_mn_with_external_collateral(self, dashd):
        has_collateral, collateral_tx, cout = self.get_collateral()
        if not has_collateral:
            collateral_tx = dashd.rpc_command("sendtoaddress",
                                              self.collateral_address, 1000.0)
            cout = 0
        key = dashd.rpc_command("getnewaddress")
        blsKey = dashd.rpc_command('bls', 'generate')
        tx = dashd.rpc_command('protx', 'register_prepare', collateral_tx,
                                 cout, '0', key, blsKey['public'],
                                 key, 0, self.collateral_address)
        print(tx)
        signed = self.client.call(
            messages.SignMessage(
                coin_name='Dash Testnet',
                address_n=parse_path("44'/1'/0'/0/0/0"),
                message=normalize_nfc(tx['signMessage']),
                script_type=messages.InputScriptType.SPENDADDRESS
            )
        )
        print(signed)
        signature = base64.b64encode(signed.signature).decode("utf-8")
        print(signature)
        res = dashd.rpc_command('protx', 'register_submit', tx['tx'], signature)
        print(res)

    def get_register_mn_protx(self, operatorKey, operatorReward):
        # prepare inputs
        txes = {}
        inputs = []
        trezor_address_data = self.api.get_addr_utxo(self.address)
        in_amount = Decimal(0.0)
        fee = Decimal(0.0)
        hash_writer = HashWriter()
        for utxo in trezor_address_data:
            if in_amount >= Decimal(1000.0) + fee:
                break
            fee = fee + Decimal(0.00001)
            new_input = messages.TxInputType(
                address_n=self.bip32_path,
                prev_hash=bytes.fromhex(utxo['txid']),
                prev_index=int(utxo['vout']),
                amount=int(Decimal(utxo['amount']) * _DASH_COIN),
                script_type=messages.InputScriptType.SPENDADDRESS,
                sequence=0xFFFFFFFF,
            )
            in_amount += Decimal(utxo['amount'])
            inputs.append(new_input)
            txes[bytes.fromhex(utxo['txid'])] = self.api.get_tx(utxo['txid'])
            hash_writer.add_data(reverse_bytes(bytes.fromhex(utxo['txid'])))
            hash_writer.add_data(int(utxo['vout']).to_bytes(4, "little"))

        # prepare outputs
        outputs = []
        new_output = messages.TxOutputType(
            address_n=None,
            address=self.collateral_address,
            amount=int(1000 * _DASH_COIN),
            script_type=messages.OutputScriptType.PAYTOADDRESS
        )
        outputs.append(new_output)
        change = int((in_amount - fee) * _DASH_COIN) - int(1000 * _DASH_COIN)
        if change > 1000:
            change_output = messages.TxOutputType(
                address_n=self.bip32_path,
                address=None,
                amount=change,
                script_type=messages.OutputScriptType.PAYTOADDRESS
            )
            outputs.append(change_output)

        inputsHash = hash_writer.get_hash()
        print("inputsHash: ", inputsHash.hex())
        payload = dash_proregtx_payload(0, "0.0.0.0", 0,
                                        keyid_from_address(self.owner_address),
                                        operatorKey,
                                        keyid_from_address(self.owner_address),
                                        keyid_from_address(self.address),
                                        operatorReward, inputsHash)

        # transaction details
        signtx = messages.SignTx()
        signtx.version = 65539 # (1 << 16) & 3
        signtx.lock_time = 0

        # sign transaction
        _, signed_tx = dash_sign_tx(
            self.client, inputs, outputs, details=signtx, prev_txes=txes, extra_payload=payload
        )

        return signed_tx

    def move_collateral_to_base(self):
        # prepare inputs
        txes = {}
        inputs = []
        trezor_address_data = self.api.get_addr_utxo(self.collateral_address)
        in_amount = Decimal(0.0)
        fee = Decimal(0.0)
        for utxo in trezor_address_data:
            fee = fee + Decimal(0.00001)
            new_input = messages.TxInputType(
                address_n=parse_path("44'/1'/0'/0/0/0"),
                prev_hash=bytes.fromhex(utxo['txid']),
                prev_index=int(utxo['vout']),
                amount=int(Decimal(utxo['amount']) * _DASH_COIN),
                script_type=messages.InputScriptType.SPENDADDRESS,
                sequence=0xFFFFFFFF,
            )
            in_amount += Decimal(utxo['amount'])
            inputs.append(new_input)
            print("Txid: ", utxo['txid'])
            txes[bytes.fromhex(utxo['txid'])] = self.api.get_tx(utxo['txid'])

        in_amount -= fee

        # prepare outputs
        outputs = []
        new_output = messages.TxOutputType(
            address_n=self.bip32_path,
            address=None,
            amount=int(in_amount * _DASH_COIN),
            script_type=messages.OutputScriptType.PAYTOADDRESS
        )
        outputs.append(new_output)

        # transaction details
        signtx = messages.SignTx()
        signtx.version = 2
        signtx.lock_time = 0

        # sign transaction
        _, signed_tx = dash_sign_tx(
            self.client, inputs, outputs, details=signtx, prev_txes=txes
        )

        return signed_tx


def main():
    # Use first connected device
    transport = get_debug_transport()

    # Creates object for manipulating TREZOR
    client = TrezorClientDebugLink(transport=transport)

    dashd = DashdApi.from_dash_conf(DashConfig.get_default_dash_conf())

    # api to get balance, etc
    # api = InsightApi('https://testnet-insight.dashevo.org/insight-api/')
    api = LocalInfoApi(dashd)

    # Load custom configuration to use device with the same params
    seed = "material humble noble wrestle hen infant quote world name result cake ankle snack buffalo donor vessel chalk bamboo remove announce valid snack alarm index"
    with DashTrezor(client, api, seed) as dash_trezor:
        print('Trezor address:', dash_trezor.address)
        print('Trezor balance:', dash_trezor.trezor_balance())
        print('Trezor collateral address:', dash_trezor.collateral_address)
        print('Trezor collateral balance:', dash_trezor.trezor_balance(dash_trezor.collateral_address))

        #signed_tx = dash_trezor.send_to_address("yPD5e2HPC1m2bJnnqprrrHbGwk8ujFBHRc", 0.01)
        #txstruct = dashd.rpc_command("decoderawtransaction", signed_tx.hex())
        #print(txstruct)
        #dashd.rpc_command("sendrawtransaction", signed_tx.hex())
        #dash_trezor.register_mn_with_external_collateral(dashd)
        #dashd.rpc_command("sendtoaddress", dash_trezor.address, 1001)
        blsKey = dashd.rpc_command('bls', 'generate')
        tx = dash_trezor.get_register_mn_protx(blsKey['public'], 0)
        #tx = dash_trezor.move_collateral_to_base()
        txstruct = dashd.rpc_command("decoderawtransaction", tx.hex())
        print(txstruct)
        txid = dashd.rpc_command("sendrawtransaction", tx.hex())
        print(txid)

    client.close()


if __name__ == '__main__':
    main()
