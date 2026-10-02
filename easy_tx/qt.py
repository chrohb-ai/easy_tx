from functools import partial
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QLineEdit,
                             QPlainTextEdit, QPushButton, QSpinBox, QComboBox, QTreeWidget, QTreeWidgetItem,
                             QAbstractItemView, QApplication, QInputDialog, QCheckBox)

from electrum.plugin import hook
from electrum.i18n import _
from electrum.bitcoin import is_address
from electrum.transaction import PartialTxInput, PartialTxOutput, Transaction, tx_from_any
from electrum.gui.qt.util import WaitingDialog, Buttons, CloseButton
from electrum.gui.qt.amountedit import BTCAmountEdit
from electrum.gui.qt.qrtextedit import ShowQRTextEdit

from .easy_tx import (EasyTxPlugin, WalletDescriptor, OutputMatch, get_wallet_descriptor, load_transaction,
                      make_input, make_sequence, describe_sequence, build_psbt, MAX_RELATIVE_LOCKTIME)

if TYPE_CHECKING:
    from electrum.gui.qt.main_window import ElectrumWindow


DESCRIPTOR_PLACEHOLDER = (
    'e.g. wpkh([fingerprint/84h/0h/0h]xpub.../<0;1>/*)#checksum or '
    'wsh(sortedmulti(2,[fingerprint1/48h/0h/0h/2h]xpub1.../<0;1>/*,'
    '[fingerprint2/48h/0h/0h/2h]xpub2.../<0;1>/*))#checksum'
)

DEFAULT_GAP_LIMIT = 20


class Plugin(EasyTxPlugin):

    @hook
    def init_menubar(self, window: 'ElectrumWindow'):
        window.tools_menu.addAction(_('Easy TX'), partial(self.show_psbt_dialog, window))

    def requires_settings(self) -> bool:
        return True

    def settings_dialog(self, parent):
        # opened from the Plugins window, which is not tied to a wallet window
        from electrum.gui.qt.main_window import ElectrumWindow
        windows = [w for w in QApplication.topLevelWidgets() if isinstance(w, ElectrumWindow) and w.isVisible()]
        if not windows:
            parent.show_error(_('Open a wallet first.'))
            return
        # the Plugins window is modal, so our dialog must be its child (and modal) to receive input
        CreatePSBTDialog(windows[0], parent=parent).exec()

    def show_psbt_dialog(self, window: 'ElectrumWindow'):
        d = CreatePSBTDialog(window)
        d.show()
        d.raise_()
        d.activateWindow()


class CreatePSBTDialog(QDialog):

    def __init__(self, window: 'ElectrumWindow', *, parent=None):
        QDialog.__init__(self, parent or window)
        self.window = window
        self.setWindowTitle(_('Easy TX: Create PSBT'))
        self.setMinimumWidth(900)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        self.inputs = []  # type: List[PartialTxInput]
        self.outputs = []  # type: List[PartialTxOutput]
        self.xpubs = {}  # global PSBT xpubs, collected from the descriptors of added inputs
        # result of the last "Show outputs"
        self.loaded_tx = None  # type: Optional[Transaction]
        self.loaded_desc = None  # type: Optional[WalletDescriptor]
        self.loaded_matches = {}  # type: Dict[int, OutputMatch]
        # addresses per descriptor branch searched by "Show outputs"; raised on demand if nothing matches
        self.gap_limit = max(DEFAULT_GAP_LIMIT, getattr(window.wallet, 'gap_limit', DEFAULT_GAP_LIMIT))

        vbox = QVBoxLayout(self)
        vbox.addWidget(self._create_descriptor_box())
        vbox.addWidget(self._create_source_box())
        vbox.addWidget(self._create_outputs_box())
        vbox.addWidget(self._create_result_box())
        vbox.addLayout(Buttons(CloseButton(self)))
        self._update_summary()

    # --- layout ---

    def _create_descriptor_box(self) -> QGroupBox:
        box = QGroupBox(_('Wallet'))
        vbox = QVBoxLayout(box)
        vbox.addWidget(QLabel(_('Descriptor of the wallet you want to spend a UTXO from')))
        self.descriptor_edit = QPlainTextEdit()
        self.descriptor_edit.setPlaceholderText(DESCRIPTOR_PLACEHOLDER)
        self.descriptor_edit.setMaximumHeight(70)
        try:
            self.descriptor_edit.setPlainText(get_wallet_descriptor(self.window.wallet))
        except ValueError:
            pass
        vbox.addWidget(self.descriptor_edit)
        return box

    def _create_source_box(self) -> QGroupBox:
        box = QGroupBox(_('Add inputs'))
        vbox = QVBoxLayout(box)
        vbox.addWidget(QLabel(_('Transaction containing the UTXO: txid, raw transaction (hex) or PSBT')))
        self.source_edit = QPlainTextEdit()
        self.source_edit.setMaximumHeight(60)
        vbox.addWidget(self.source_edit)
        show_button = QPushButton(_('Show outputs'))
        show_button.clicked.connect(self.on_show_outputs)
        vbox.addLayout(Buttons(show_button))

        self.source_outputs_list = QTreeWidget()
        self.source_outputs_list.setHeaderLabels(['#', _('Address'), _('Amount'), _('In wallet descriptor')])
        self.source_outputs_list.setRootIsDecorated(False)
        self.source_outputs_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.source_outputs_list.setMaximumHeight(130)
        self.source_outputs_list.itemSelectionChanged.connect(self._update_add_input_button)
        vbox.addWidget(self.source_outputs_list)

        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(_('Relative locktime')))
        self.rel_locktime_spin = QSpinBox()
        self.rel_locktime_spin.setRange(0, MAX_RELATIVE_LOCKTIME)
        self.rel_locktime_spin.setToolTip(_('BIP-68 relative locktime (nSequence); 0 = disabled'))
        hbox.addWidget(self.rel_locktime_spin)
        self.rel_locktime_unit = QComboBox()
        self.rel_locktime_unit.addItems([_('blocks'), _('× 512 seconds')])
        hbox.addWidget(self.rel_locktime_unit)
        hbox.addStretch(1)
        self.add_input_button = QPushButton(_('Add selected output as input'))
        self.add_input_button.clicked.connect(self.on_add_input)
        self.add_input_button.setEnabled(False)
        hbox.addWidget(self.add_input_button)
        vbox.addLayout(hbox)

        vbox.addWidget(QLabel(_('Inputs of the new transaction')))
        self.inputs_list = QTreeWidget()
        self.inputs_list.setHeaderLabels([_('Outpoint'), _('Address'), _('Amount'), _('Path'), _('Relative locktime')])
        self.inputs_list.setRootIsDecorated(False)
        self.inputs_list.setMaximumHeight(110)
        vbox.addWidget(self.inputs_list)
        remove_button = QPushButton(_('Remove selected input'))
        remove_button.clicked.connect(self.on_remove_input)
        vbox.addLayout(Buttons(remove_button))
        return box

    def _create_outputs_box(self) -> QGroupBox:
        box = QGroupBox(_('Add Outputs'))
        vbox = QVBoxLayout(box)
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(_('Address')))
        self.address_edit = QLineEdit()
        hbox.addWidget(self.address_edit, 3)
        hbox.addWidget(QLabel(_('Amount')))
        self.amount_edit = BTCAmountEdit(self.window.get_decimal_point)
        hbox.addWidget(self.amount_edit, 1)
        add_output_button = QPushButton(_('Add output'))
        add_output_button.clicked.connect(self.on_add_output)
        hbox.addWidget(add_output_button)
        vbox.addLayout(hbox)

        self.outputs_list = QTreeWidget()
        self.outputs_list.setHeaderLabels([_('Address'), _('Amount')])
        self.outputs_list.setRootIsDecorated(False)
        self.outputs_list.setMaximumHeight(110)
        vbox.addWidget(self.outputs_list)
        remove_button = QPushButton(_('Remove selected output'))
        remove_button.clicked.connect(self.on_remove_output)
        vbox.addLayout(Buttons(remove_button))
        return box

    def _create_result_box(self) -> QGroupBox:
        box = QGroupBox(_('Create Transaction'))
        vbox = QVBoxLayout(box)
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(_('nLockTime')))
        self.locktime_edit = QLineEdit('0')
        self.locktime_edit.setToolTip(_('0 = disabled; < 500000000 = block height; otherwise UNIX timestamp'))
        self.locktime_edit.setMaximumWidth(150)
        hbox.addWidget(self.locktime_edit)
        hbox.addSpacing(20)
        self.rbf_checkbox = QCheckBox(_('Signal replace-by-fee'))
        self.rbf_checkbox.setChecked(True)
        self.rbf_checkbox.setToolTip(_('Allow the transaction to be replaced by one paying a higher fee (BIP-125). '
                                       'Inputs with a relative locktime always signal replace-by-fee.'))
        hbox.addWidget(self.rbf_checkbox)
        hbox.addStretch(1)
        vbox.addLayout(hbox)
        self.summary_label = QLabel()
        vbox.addWidget(self.summary_label)
        build_button = QPushButton(_('Build PSBT'))
        build_button.clicked.connect(self.on_build_psbt)
        self.open_button = QPushButton(_('Open in Electrum'))
        self.open_button.setToolTip(_('Show the PSBT in Electrum\'s transaction dialog, e.g. to sign or export it'))
        self.open_button.clicked.connect(self.on_open_psbt)
        self.open_button.setEnabled(False)
        vbox.addLayout(Buttons(build_button, self.open_button))
        self.psbt_edit = ShowQRTextEdit(config=self.window.config)
        self.psbt_edit.addCopyButton()
        self.psbt_edit.setMaximumHeight(100)
        vbox.addWidget(self.psbt_edit)
        self.psbt = None
        self.locktime_edit.textChanged.connect(self._invalidate_psbt)
        self.rbf_checkbox.toggled.connect(self._invalidate_psbt)
        return box

    # --- helpers ---

    def _fmt(self, sats: Optional[int]) -> str:
        return self.window.format_amount_and_units(sats) if sats is not None else _('unknown')

    def _invalidate_psbt(self):
        self.psbt = None
        self.psbt_edit.setPlainText('')
        self.open_button.setEnabled(False)
        self._update_summary()

    def _update_summary(self):
        total_in = sum(txin.value_sats() for txin in self.inputs)
        total_out = sum(txout.value for txout in self.outputs)
        text = _('Inputs') + f': {self._fmt(total_in)}    ' + _('Outputs') + f': {self._fmt(total_out)}    '
        text += _('Fee') + f': {self._fmt(total_in - total_out)}'
        self.summary_label.setText(text)

    def _update_add_input_button(self):
        idx = self._selected_source_output()
        self.add_input_button.setEnabled(idx is not None and idx in self.loaded_matches)

    def _selected_source_output(self) -> Optional[int]:
        items = self.source_outputs_list.selectedItems()
        if not items:
            return None
        return items[0].data(0, Qt.ItemDataRole.UserRole)

    def _match_label(self, desc: WalletDescriptor, match: OutputMatch) -> str:
        label = desc.branch_label(match.branch)
        if match.pos is not None:
            label += f' #{match.pos}'
        return _('yes') + f' ({label})'

    # --- actions ---

    def on_show_outputs(self):
        try:
            desc = WalletDescriptor(self.descriptor_edit.toPlainText())
        except Exception as e:
            self.window.show_error(_('Invalid descriptor') + f':\n{e}', parent=self)
            return
        source = self.source_edit.toPlainText()

        def on_error(exc_info):
            self.window.show_error(_('Could not load transaction') + f':\n{exc_info[1]}', parent=self)

        WaitingDialog(self, _('Loading transaction...'), lambda: load_transaction(source),
                      lambda tx: self._scan_outputs(tx, desc, self.gap_limit), on_error)

    def _scan_outputs(self, tx: Transaction, desc: WalletDescriptor, gap_limit: int):
        def task():
            scripts = desc.find_scripts(gap_limit)
            return {i: scripts[o.scriptpubkey] for i, o in enumerate(tx.outputs()) if o.scriptpubkey in scripts}

        def on_success(matches: Dict[int, OutputMatch]):
            self._show_outputs(tx, desc, matches)
            if matches:
                self.gap_limit = max(self.gap_limit, gap_limit)  # keep searching this deep for further txs
                return
            new_gap_limit, ok = QInputDialog.getInt(
                self, _('No matching output'),
                _('No output of this transaction belongs to the wallet descriptor '
                  '(searched the first {} addresses of each branch).').format(gap_limit) + '\n\n'
                + _('Search more addresses? Number of addresses per branch:'),
                value=gap_limit * 5, min=gap_limit + 1, max=1_000_000)
            if ok:
                self._scan_outputs(tx, desc, new_gap_limit)

        def on_error(exc_info):
            self.window.show_error(_('Could not scan outputs') + f':\n{exc_info[1]}', parent=self)

        WaitingDialog(self, _('Searching {} addresses per branch...').format(gap_limit), task, on_success, on_error)

    def _show_outputs(self, tx: Transaction, desc: WalletDescriptor, matches: Dict[int, OutputMatch]):
        self.loaded_tx, self.loaded_desc, self.loaded_matches = tx, desc, matches
        self.source_outputs_list.clear()
        for i, o in enumerate(tx.outputs()):
            mine = self._match_label(desc, matches[i]) if i in matches else _('no')
            item = QTreeWidgetItem([str(i), o.address or o.scriptpubkey.hex(), self._fmt(o.value), mine])
            item.setData(0, Qt.ItemDataRole.UserRole, i)
            self.source_outputs_list.addTopLevelItem(item)
            if i in matches and not self.source_outputs_list.selectedItems():
                item.setSelected(True)
        for col in range(4):
            self.source_outputs_list.resizeColumnToContents(col)
        self._update_add_input_button()

    def on_add_input(self):
        idx = self._selected_source_output()
        if idx is None or idx not in self.loaded_matches:
            return
        tx, desc, match = self.loaded_tx, self.loaded_desc, self.loaded_matches[idx]
        if any(txin.prevout.txid.hex() == tx.txid() and txin.prevout.out_idx == idx for txin in self.inputs):
            self.window.show_error(_('This output was already added as input.'), parent=self)
            return
        try:
            nsequence = make_sequence(self.rel_locktime_spin.value(), self.rel_locktime_unit.currentIndex() == 1)
            concrete = desc.concrete_descriptor(match)
            txin = make_input(tx, idx, concrete, nsequence)
        except Exception as e:
            self.window.show_error(_('Could not add input') + f':\n{e}', parent=self)
            return
        self.inputs.append(txin)
        self.xpubs.update(desc.global_xpubs())
        path = desc.branch_label(match.branch) + (f' #{match.pos}' if match.pos is not None else '')
        self.inputs_list.addTopLevelItem(QTreeWidgetItem([
            txin.prevout.to_str(), txin.address or '', self._fmt(txin.value_sats()), path, describe_sequence(nsequence)]))
        for col in range(5):
            self.inputs_list.resizeColumnToContents(col)
        self._invalidate_psbt()

    def on_remove_input(self):
        item = self.inputs_list.currentItem()
        if item is None:
            return
        del self.inputs[self.inputs_list.indexOfTopLevelItem(item)]
        self.inputs_list.takeTopLevelItem(self.inputs_list.indexOfTopLevelItem(item))
        self._invalidate_psbt()

    def on_add_output(self):
        address = self.address_edit.text().strip()
        if not is_address(address):
            self.window.show_error(_('Invalid address for this network'), parent=self)
            return
        amount = self.amount_edit.get_amount()
        if not amount or amount <= 0:
            self.window.show_error(_('Enter a positive amount'), parent=self)
            return
        txout = PartialTxOutput.from_address_and_value(address, amount)
        self.outputs.append(txout)
        self.outputs_list.addTopLevelItem(QTreeWidgetItem([address, self._fmt(amount)]))
        self.outputs_list.resizeColumnToContents(0)
        self.address_edit.clear()
        self.amount_edit.clear()
        self._invalidate_psbt()

    def on_remove_output(self):
        item = self.outputs_list.currentItem()
        if item is None:
            return
        del self.outputs[self.outputs_list.indexOfTopLevelItem(item)]
        self.outputs_list.takeTopLevelItem(self.outputs_list.indexOfTopLevelItem(item))
        self._invalidate_psbt()

    def on_build_psbt(self):
        try:
            locktime = int(self.locktime_edit.text().strip() or '0')
            psbt = build_psbt(self.inputs, self.outputs, locktime=locktime, xpubs=self.xpubs,
                              rbf=self.rbf_checkbox.isChecked())
        except Exception as e:
            self.window.show_error(_('Could not build PSBT') + f':\n{e}', parent=self)
            return
        fee = psbt.get_fee()
        if fee is not None and fee < 0:
            self.window.show_error(_('Outputs exceed inputs by {}').format(self._fmt(-fee)), parent=self)
            return
        self.psbt = psbt
        self.psbt_edit.setPlainText(psbt.serialize_as_bytes(force_psbt=True).hex())
        self.open_button.setEnabled(True)

    def on_open_psbt(self):
        if self.psbt is not None:
            self.window.show_transaction(tx_from_any(self.psbt.serialize()))
