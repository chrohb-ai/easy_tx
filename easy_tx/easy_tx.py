import re
from typing import TYPE_CHECKING, Dict, List, NamedTuple, Optional, Sequence, Tuple, Union

from electrum import constants
from electrum.plugin import BasePlugin
from electrum.descriptor import AddChecksum, DescriptorChecksum, Descriptor, PubkeyProvider, parse_descriptor
from electrum.keystore import Xpub
from electrum.network import Network
from electrum.transaction import (PartialTransaction, PartialTxInput, PartialTxOutput, Transaction,
                                  TxOutpoint, tx_from_any)
from electrum.wallet import Standard_Wallet, Multisig_Wallet

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet


# receive and change branches, as a BIP-389 multipath expression
DERIV_SUFFIX = '/<0;1>/*'

SINGLESIG_TEMPLATES = {
    'p2pkh': 'pkh({})',
    'p2wpkh': 'wpkh({})',
    'p2wpkh-p2sh': 'sh(wpkh({}))',
}
MULTISIG_TEMPLATES = {
    'p2sh': 'sh({})',
    'p2wsh': 'wsh({})',
    'p2wsh-p2sh': 'sh(wsh({}))',
}

MEMPOOL_API = {
    'mainnet': 'https://mempool.space/api',
    'testnet': 'https://mempool.space/testnet/api',
    'testnet4': 'https://mempool.space/testnet4/api',
    'signet': 'https://mempool.space/signet/api',
    'mutinynet': 'https://mutinynet.com/api',
}

# nSequence without relative locktime: signals RBF and keeps nLockTime enforced
SEQUENCE_NO_RELATIVE_LOCKTIME = 0xfffffffd
# nSequence without relative locktime and without RBF signal; nLockTime is still enforced
SEQUENCE_NO_RELATIVE_LOCKTIME_NO_RBF = 0xfffffffe
SEQUENCE_TYPE_FLAG = 1 << 22  # BIP-68: relative locktime in units of 512 seconds
MAX_RELATIVE_LOCKTIME = 0xffff


def keystore_to_key_expr(ks: 'Xpub') -> str:
    """Returns e.g. [fingerprint/84h/1h/0h]tpub.../<0;1>/*"""
    # descriptors always use standard xpub/tpub serialization (not ypub/zpub/vpub)
    node = ks.get_bip32_node_for_xpub()._replace(xtype='standard')
    origin = ''
    fingerprint = ks.get_root_fingerprint()
    if fingerprint:
        path = (ks.get_derivation_prefix() or 'm').replace("'", 'h')
        path = path[1:] if path.startswith('m') else path
        origin = f'[{fingerprint}{path}]'
    return origin + node.to_xpub() + DERIV_SUFFIX


def get_wallet_descriptor(wallet: 'Abstract_Wallet') -> str:
    """Returns the output descriptor (with checksum) covering the wallet's receive and change addresses."""
    keystores = wallet.get_keystores()
    if not keystores or not all(isinstance(ks, Xpub) for ks in keystores):
        raise ValueError('wallet has no extended public keys')
    txin_type = wallet.txin_type
    if isinstance(wallet, Standard_Wallet):
        template = SINGLESIG_TEMPLATES.get(txin_type)
        inner = keystore_to_key_expr(keystores[0])
    elif isinstance(wallet, Multisig_Wallet):
        template = MULTISIG_TEMPLATES.get(txin_type)
        keys = ','.join(keystore_to_key_expr(ks) for ks in keystores)
        inner = f'sortedmulti({wallet.m},{keys})'
    else:
        template = None
    if template is None:
        raise ValueError(f'unsupported wallet type: {wallet.wallet_type} / {txin_type}')
    return AddChecksum(template.format(inner))


def iter_pubkey_providers(desc: Descriptor):
    yield from desc.pubkeys
    for sub in desc.subdescriptors:
        yield from iter_pubkey_providers(sub)


class OutputMatch(NamedTuple):
    branch: int  # index into the multipath expression (0 = receive, 1 = change for <0;1>)
    pos: Optional[int]  # address index, None for non-ranged descriptors


class WalletDescriptor:
    """A (possibly BIP-389 multipath) output descriptor, split into one descriptor per branch."""

    def __init__(self, desc_str: str):
        desc_str = re.sub(r'\s', '', desc_str)
        if not desc_str:
            raise ValueError('descriptor is empty')
        body, _, checksum = desc_str.partition('#')
        if checksum and DescriptorChecksum(body) != checksum:
            raise ValueError(f'descriptor checksum mismatch: got {checksum}, expected {DescriptorChecksum(body)}')
        self.branch_strs = self._expand_multipath(body)
        self.branches = [parse_descriptor(s) for s in self.branch_strs]

    @staticmethod
    def _expand_multipath(body: str) -> List[str]:
        groups = re.findall(r'<([0-9h\';]+)>', body)
        if not groups:
            return [body]
        options = [g.split(';') for g in groups]
        n = len(options[0])
        if n < 2 or any(len(o) != n for o in options):
            raise ValueError('all multipath expressions <a;b;...> must have the same number (>= 2) of elements')
        result = []
        for i in range(n):
            it = iter(o[i] for o in options)
            result.append(re.sub(r'<[0-9h\';]+>', lambda m: next(it), body))
        return result

    def branch_label(self, branch: int) -> str:
        if len(self.branches) == 2:
            return ('receive', 'change')[branch]
        return f'branch {branch}'

    def find_scripts(self, gap_limit: int) -> Dict[bytes, OutputMatch]:
        """Returns scriptpubkey -> OutputMatch for the first `gap_limit` addresses of every branch."""
        scripts = {}
        for branch, desc in enumerate(self.branches):
            if desc.is_range():
                for pos in range(gap_limit):
                    scripts[desc.expand(pos=pos).output_script] = OutputMatch(branch, pos)
            else:
                scripts[desc.expand().output_script] = OutputMatch(branch, None)
        return scripts

    def concrete_descriptor(self, match: OutputMatch) -> Descriptor:
        """Returns a non-ranged descriptor for a single address."""
        s = self.branch_strs[match.branch]
        if match.pos is not None:
            s = s.replace('*', str(match.pos))
        return parse_descriptor(s)

    def global_xpubs(self) -> Dict:
        """Returns BIP32Node -> (root fingerprint, derivation path) for the PSBT global xpub section."""
        xpubs = {}
        for pp in iter_pubkey_providers(self.branches[0]):
            if pp.extkey is not None and pp.origin is not None:
                xpubs[pp.extkey] = (pp.origin.fingerprint, list(pp.origin.path))
        return xpubs


def fill_bip32_paths(txin: PartialTxInput, desc: Descriptor) -> None:
    """Fills the PSBT BIP32 derivation fields of txin from a non-ranged descriptor."""
    for pp in iter_pubkey_providers(desc):
        if pp.extkey is None:
            continue
        if pp.origin is not None:
            fingerprint, path = pp.origin.fingerprint, list(pp.origin.path)
        else:
            fingerprint, path = pp.extkey.calc_fingerprint_of_this_node(), []
        # note: pp.get_full_derivation_int_list() would prepend the fingerprint to the path
        txin.bip32_paths[pp.get_pubkey_bytes()] = (fingerprint, path + pp.get_der_suffix_int_list())


def get_mempool_api_url() -> str:
    url = MEMPOOL_API.get(constants.net.NET_NAME)
    if url is None:
        raise ValueError(f'no mempool API known for network {constants.net.NET_NAME!r}; paste the raw transaction instead')
    return url


def load_transaction(text: str) -> Union[Transaction, PartialTransaction]:
    """Loads a tx from a txid (fetched from the mempool API), raw tx hex, or PSBT (hex or base64).
    Blocking; call from a non-GUI thread."""
    text = re.sub(r'\s', '', text)
    if not text:
        raise ValueError('enter a txid, raw transaction or PSBT')
    if re.fullmatch(r'[0-9a-fA-F]{64}', text):
        raw = Network.send_http_on_proxy('get', f'{get_mempool_api_url()}/tx/{text.lower()}/hex', timeout=30)
        tx = tx_from_any(raw.strip())
        if tx.txid() != text.lower():
            raise ValueError('mempool API returned a transaction with a different txid')
        return tx
    tx = tx_from_any(text)
    if tx.txid() is None:
        raise ValueError('cannot compute the txid of this PSBT (it has non-segwit inputs and is not fully signed)')
    return tx


def make_sequence(relative_locktime: int, in_time_units: bool) -> int:
    if relative_locktime == 0:
        return SEQUENCE_NO_RELATIVE_LOCKTIME
    if not 0 < relative_locktime <= MAX_RELATIVE_LOCKTIME:
        raise ValueError(f'relative locktime must be between 0 and {MAX_RELATIVE_LOCKTIME}')
    return relative_locktime | (SEQUENCE_TYPE_FLAG if in_time_units else 0)


def describe_sequence(nsequence: int) -> str:
    if nsequence >= SEQUENCE_NO_RELATIVE_LOCKTIME:
        return 'none'
    value = nsequence & MAX_RELATIVE_LOCKTIME
    if nsequence & SEQUENCE_TYPE_FLAG:
        return f'{value} × 512 s'
    return f'{value} blocks'


def make_input(parent: Transaction, out_idx: int, desc: Descriptor, nsequence: int) -> PartialTxInput:
    txin = PartialTxInput(prevout=TxOutpoint(txid=bytes.fromhex(parent.txid()), out_idx=out_idx),
                          nsequence=nsequence)
    if parent.is_complete():
        txin.utxo = parent
    if desc.is_segwit():
        txin.witness_utxo = parent.outputs()[out_idx]
    if txin.utxo is None and txin.witness_utxo is None:
        raise ValueError('a non-segwit output of an unsigned PSBT cannot be spent (its full transaction is not final)')
    txin.script_descriptor = desc
    fill_bip32_paths(txin, desc)
    return txin


def build_psbt(
        inputs: Sequence[PartialTxInput],
        outputs: Sequence[PartialTxOutput],
        *,
        locktime: int,
        xpubs: Dict,
        rbf: bool = True,
) -> PartialTransaction:
    if not inputs:
        raise ValueError('add at least one input')
    if not outputs:
        raise ValueError('add at least one output')
    if not 0 <= locktime <= 0xffffffff:
        raise ValueError('nLockTime must be between 0 and 4294967295')
    # version 2 is required for BIP-68 relative locktimes
    # inputs with a relative locktime always signal RBF (BIP-125); only the others are affected
    for txin in inputs:
        if txin.nsequence >= SEQUENCE_NO_RELATIVE_LOCKTIME:
            txin.nsequence = SEQUENCE_NO_RELATIVE_LOCKTIME if rbf else SEQUENCE_NO_RELATIVE_LOCKTIME_NO_RBF
    tx = PartialTransaction.from_io(list(inputs), list(outputs), locktime=locktime, version=2, BIP69_sort=False)
    tx.xpubs.update(xpubs)
    return tx


class EasyTxPlugin(BasePlugin):
    pass
