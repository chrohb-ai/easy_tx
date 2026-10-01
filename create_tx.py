
try:
    import bitcointx
except:
    print("Please run pip install python-bitcointx first")
    import sys
    sys.exit()

from bitcointx.core import lx
from bitcointx.core import CBitcoinOutPoint, CBitcoinTransaction, CBitcoinTxOut, CBitcoinTxIn
from bitcointx.core.script import CBitcoinScript
from bitcointx.core.psbt import PSBT_BitcoinInput, PSBT_BitcoinOutput, PartiallySignedBitcoinTransaction
from bitcointx.core.script import OP_CHECKMULTISIG, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_EQUAL
from bitcointx.core.key import CPubKey
from bitcointx.wallet import CBitcoinExtPubKey
from bitcointx.core.psbt import PSBT_KeyDerivationInfo
from bitcointx.core.key import BIP32Path
import json

def save(d:dict):
    with open("data.tmp","w") as f:
        f.write(json.dumps(d))
def load():
    return json.loads(open("data.tmp").read())

def read(data, key="num_inputs", text="Number of inputs", is_int=False):
    if key in data:
        value = data[key]
        #inp = ""
        inp = input(f"{text} (default: {value}): ") # TODO: uncomment
        if inp != "":
            value = inp
    else:
        value = input(f"{text}: ")
    if is_int:
        value = int(value)
    data[key] = value
    save(data)
    return value

try:
    data = load()
except:
    data = {}

print("Creating new transaction...")

# --- Collect xpub info first so we can auto-match pubkeys to fingerprints ---

num_xpubs = read(data, key="num_xpubs", text="Number of xpubs for signing", is_int=True)

xpub_info = []
for i in range(num_xpubs):
    xpub_ = read(data, key=f"xpub_{i}", text=f"xpub {i}")
    xpub = CBitcoinExtPubKey(xpub_)

    fingerprint_hex = read(data, key=f"xpub_fingerprint_{i}", text=f"Master fingerprint for xpub {xpub_}")
    fingerprint = bytes.fromhex(fingerprint_hex)

    derivation_path_str = read(data, key=f"xpub_derivation_path_{i}", text=f"Derivation for xpub {xpub_}")

    xpub_info.append({
        'xpub_str': xpub_,
        'xpub': xpub,
        'fingerprint_hex': fingerprint_hex,
        'fingerprint': fingerprint,
        'derivation_path_str': derivation_path_str,
    })

def find_fingerprint_for_pubkey(pubkey_hex, child_path):
    """Derive child keys from each xpub and return the matching fingerprint + full derivation path."""
    target = CPubKey(bytes.fromhex(pubkey_hex))
    for info in xpub_info:
        child = info['xpub'].derive_path(child_path)
        if child.pub == target:
            # Build full derivation path: xpub base path + child suffix
            base = info['derivation_path_str'].rstrip('/')
            full_path = base + '/' + child_path
            print(f"  -> Matched pubkey {pubkey_hex[:16]}... to fingerprint {info['fingerprint_hex']} (path: {full_path})")
            return info['fingerprint'], BIP32Path(full_path)
    return None, None

# --- Main input loop ---

num_inputs = read(data, key="num_inputs", text="Number of inputs", is_int=True)

txins = []
psbtins = []
for i in range(num_inputs):
    txid_vout = read(data, key=f"txid_vout_{i}", text=f"Txid:vout for input {i}")
    txid, vout = txid_vout.split(":")
    txidlx = lx(txid)
    vout = int(vout)

    outpoint = CBitcoinOutPoint(txidlx, vout)

    rbf = read(data, key=f"rbf_{i}", text=f"Replace by fee (0 or 1) for Txid:vout {txid_vout}")
    if rbf == "0":
        nSequence = 0xffffffff
    elif rbf == "1":
        nSequence = 0xfffffffd
    else:
        raise RuntimeError
    txin = CBitcoinTxIn(outpoint, nSequence=nSequence)
    txins.append(txin)

    num_inputs_ = read(data, key=f"txid_vout_{i}_num_inputs", text=f"Number of inputs for txid {txid}", is_int=True)

    txins_ = []
    for j in range(num_inputs_):
        txid_vout_ = read(data, key=f"txid_vout_{i}_{j}", text=f"Txid:vout for txid {txid} and input {j}")
        txid_, vout_ = txid_vout_.split(":")
        txid_ = lx(txid_)
        vout_ = int(vout_)

        outpoint_ = CBitcoinOutPoint(txid_, vout_)

        rbf = read(data, key=f"rbf_{i}_{j}", text=f"Replace by fee (0 or 1) for Txid:vout {txid_vout_}")
        if rbf == "0":
            nSequence = 0xffffffff
        elif rbf == "1":
            nSequence = 0xfffffffd
        else:
            raise RuntimeError
        scriptsig_ = read(data, key=f"scriptsig_{i}_{j}",
                          text=f"ScriptSig hex for txid {txid} and input {j} (empty for segwit inputs)")
        scriptSig_ = CBitcoinScript(bytes.fromhex(scriptsig_)) if scriptsig_ else CBitcoinScript()

        txin_ = CBitcoinTxIn(outpoint_, scriptSig_, nSequence=nSequence)
        txins_.append(txin_)

    num_outputs_ = read(data, key=f"txid_vout_{i}_num_outputs", text=f"Number of outputs for txid {txid}", is_int=True)

    txouts_ = []
    witness_script = None
    for j in range(num_outputs_):
        address = read(data, key=f"address_{txid}_{j}", text=f"Output address for txid {txid} and output {j}")

        if address.startswith("1") or address.startswith("3"):
            pkh = read(data, key=f"pkh_{txid}_{j}", text=f"Public Key Hash or Script Hash for txid {txid} and output {j}")
            scriptPubKey_ = read(data, key=f"scriptPubKey_{txid}_{j}", text=f"SkriptPubKey for txid {txid} and output {j}")

            script_ = []
            for op in scriptPubKey_.split():
                if op == "OP_DUP":
                    script_.append(OP_DUP)
                elif op == "OP_HASH160":
                    script_.append(OP_HASH160)
                elif op == "OP_EQUALVERIFY":
                    script_.append(OP_EQUALVERIFY)
                elif op == "OP_CHECKSIG":
                    script_.append(OP_CHECKSIG)
                elif op == "OP_EQUAL":
                    script_.append(OP_EQUAL)
                elif op == "<pkh>" or op == "<sh>":
                    pkh = CPubKey(bytes.fromhex(pkh))
                    script_.append(pkh)
                else:
                    raise NotImplementedError(f"ERROR: Unimplemented op {op}")
            script_ = CBitcoinScript(script_)
        else:
            s = read(data, key=f"wpkh_or_wsh_{txid}_{j}", text=f"Witness Public Key Hash or Witness Script Hash for txid {txid} and output {j}")
            if len(s) != 40 and j == vout:
                output_descriptor = read(data, key=f"output_descriptor_{i}", text=f"Output Descriptor for input address {i}")
                output_descriptor = output_descriptor.split(",")
                num = int(output_descriptor[0].split("(")[-1])
                pubkeys = [p.strip(")") for p in output_descriptor[1:]]

                data_ = [num, *[CPubKey(bytes.fromhex(p)) for p in pubkeys], len(pubkeys), OP_CHECKMULTISIG]
                witness_script = CBitcoinScript(data_)

            scriptPubKey_ = bytes.fromhex(s)
            script_ = CBitcoinScript([0,scriptPubKey_])

        sats = read(data, key=f"sats_{txid}_{j}", text=f"Satoshis for txid {txid} and output {j}", is_int=True)
        txout_ = CBitcoinTxOut(sats, script_)
        txouts_.append(txout_)

    nLockTime = read(data, key=f"nLockTime_{txid}", text=f"nLockTime for {txid} (0 if disabled)", is_int=True)
    nVersion = read(data, key=f"nVersion_{txid}", text=f"Headers Version for {txid} (1 or 2)", is_int=True)
    utxo = CBitcoinTransaction(txins_,txouts_, nLockTime=nLockTime, nVersion=nVersion)

    if witness_script is None:
        psbtin = PSBT_BitcoinInput(utxo=utxo, sighash_type=1)
    else:
        psbtin = PSBT_BitcoinInput(witness_script=witness_script, sighash_type=1)
        psbtin._utxo = utxo

    output_descriptor = read(data, key=f"output_descriptor_{i}", text=f"Output Descriptor for input address {i}")
    output_descriptor = output_descriptor.split(",")
    first = output_descriptor[0].split("(")[-1]
    if len(first) < 3:
        num = int(first)
        pubkeys = [p.strip(")") for p in output_descriptor[1:]]
    else:
        num = 1
        pubkeys = [first.strip(")")]

    # Ask for the child derivation suffix (e.g. "0/0" for first receive address)
    child_path = read(data, key=f"child_path_{i}", text=f"Child derivation suffix for input {i} (e.g. 0/0)")

    # Auto-match each pubkey to its fingerprint by deriving from xpubs
    print(f"Matching pubkeys to fingerprints for input {i}...")
    for j, pubkey_hex in enumerate(pubkeys):
        pubkey = CPubKey(bytes.fromhex(pubkey_hex))

        fingerprint, derivation_path = find_fingerprint_for_pubkey(pubkey_hex, child_path)
        if fingerprint is None:
            raise RuntimeError(
                f"Could not match pubkey {pubkey_hex} to any xpub using child path '{child_path}'. "
                f"Check that your xpubs and child path are correct."
            )

        der_info = PSBT_KeyDerivationInfo(fingerprint, derivation_path)
        psbtin.derivation_map[pubkey] = der_info

    psbtins.append(psbtin)

num_outputs = read(data, key="num_outputs", text="Number of outputs", is_int=True)

txouts = []
for i in range(num_outputs):
    segwit = read(data, key=f"segwit_output_{i}", text=f"Segwit output (0 or 1) for output {i}")
    s = read(data, key=f"script_output_bytes_{i}", text=f"Script Output Bytes for output {i}")
    if segwit == "1":
        if len(s) == 44 or len(s) == 68:
            s = s[4:]
        scriptPubKey = bytes.fromhex(s)

        script = CBitcoinScript([0,scriptPubKey])
    elif segwit == "0":
        # For non segwit outputs the full scriptPubKey is given (e.g. 76a914<pkh>88ac or a914<sh>87)
        script = CBitcoinScript(bytes.fromhex(s))
    else:
        raise RuntimeError
    sats = read(data, key=f"sats_{i}", text=f"Satoshis for output {i}", is_int=True)
    txout = CBitcoinTxOut(sats, script)
    txouts.append(txout)

unsigned_tx = CBitcoinTransaction(txins,txouts) #,nVersion=2)

psbtouts = [PSBT_BitcoinOutput() for _ in range(len(txouts))]

psbt = PartiallySignedBitcoinTransaction(inputs=psbtins, outputs=psbtouts, unsigned_tx=unsigned_tx)

# Add global xpub entries to the PSBT
for info in xpub_info:
    derivation_path = BIP32Path(info['derivation_path_str'])
    der_info = PSBT_KeyDerivationInfo(info['fingerprint'], derivation_path)
    psbt.xpubs[info['xpub']] = der_info

#print(psbt)
#print(psbt.inputs[0].derivation_map)

psbt_base64 = psbt.to_base64()
print(psbt_base64)
