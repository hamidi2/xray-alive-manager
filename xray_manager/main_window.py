"""Main window of the Xray connection manager."""
from __future__ import annotations

import json
import shutil
import subprocess

try:
    from PyQt6 import QtCore, QtGui, QtWidgets
    Signal = QtCore.pyqtSignal
except ImportError:
    from PySide6 import QtCore, QtGui, QtWidgets
    Signal = QtCore.Signal

try:
    from . import config_io, link_parser, tester
    from .link_parser import _address_of
    from .state import State
except ImportError:  # running as a plain script
    import config_io, link_parser, tester
    from link_parser import _address_of
    from state import State

COLS = ["#", "Name", "Protocol", "Address:Port", "Serving Ports", "Status", "Ping", "Enabled"]
CHECK_COL = len(COLS) - 1  # the enable/disable checkbox column
ST_UNKNOWN, ST_CHECKING, ST_ALIVE, ST_DEAD = "?", "…", "alive", "dead"


class TestWorker(QtCore.QRunnable):
    class Signals(QtCore.QObject):
        done = Signal(str, dict)

    def __init__(self, key: str, xray_bin: str, outbound: dict, url: str, timeout: int):
        super().__init__()
        self.sig = self.Signals()
        self.args = (key, xray_bin, outbound, url, timeout)

    def run(self):
        key, xbin, ob, url, timeout = self.args
        try:
            if not xbin:
                result = {"ok": False, "ping_ms": None, "error": "xray binary not found"}
            else:
                result = tester.test_outbound(xbin, ob, url, timeout)
        except Exception as e:  # noqa: BLE001
            result = {"ok": False, "ping_ms": None, "error": str(e)}
        try:
            self.sig.done.emit(key, result)
        except RuntimeError:
            pass  # window closed mid-test; no receiver left


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Xray Connection Manager")
        self.resize(980, 620)
        self.state = State()
        self.results: dict[str, dict] = {}  # key -> test result
        self.rows: list[dict] = []          # [{outbound, key, enabled}]
        self._config = {}                   # last config read (for the ports column)
        self._pending: set[str] = set()     # keys of tests still in flight
        self.pool = QtCore.QThreadPool.globalInstance()
        self.pool.setMaxThreadCount(6)  # too many concurrent tests -> bandwidth contention -> flaky results
        self._build_ui()
        self.reload()
        self._test_all()  # one initial test on startup
        # periodic refresh only updates the service status label; tests run on demand only
        self._timer = QtCore.QTimer(self)
        self._timer.setInterval(30000)
        self._timer.timeout.connect(self._refresh_service)
        self._timer.start()

    # ---------------- UI ----------------
    def _build_ui(self):
        root = QtWidgets.QWidget()
        self.setCentralWidget(root)
        lay = QtWidgets.QVBoxLayout(root)

        # top bar: paths and service status
        top = QtWidgets.QHBoxLayout()
        top.addWidget(QtWidgets.QLabel("Config:"))
        self.path_edit = QtWidgets.QLineEdit(self.state.data["config_path"])
        self.path_edit.editingFinished.connect(self._on_path_changed)
        top.addWidget(self.path_edit, 1)
        b_pick = QtWidgets.QPushButton(QtGui.QIcon.fromTheme("document-open"), "")
        b_pick.setToolTip("Choose the config file")
        b_pick.clicked.connect(self._pick_config)
        top.addWidget(b_pick)
        self.lbl_service = QtWidgets.QLabel("Service: —")
        top.addWidget(self.lbl_service)
        b_service = QtWidgets.QPushButton("Service status")
        b_service.clicked.connect(self._refresh_service)
        top.addWidget(b_service)
        lay.addLayout(top)

        # connections table
        self.table = QtWidgets.QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.itemDoubleClicked.connect(lambda *_: self._edit_selected())
        self.table.itemChanged.connect(self._on_item_changed)
        self.table.itemSelectionChanged.connect(self._show_selected_link)
        lay.addWidget(self.table, 1)

        # box showing the full link of the selected connection
        lay.addWidget(QtWidgets.QLabel("Selected connection link:"))
        self.link_box = QtWidgets.QPlainTextEdit()
        self.link_box.setReadOnly(True)
        self.link_box.setMaximumHeight(72)
        self.link_box.setPlaceholderText("Click a row in the table to see its full link here…")
        lay.addWidget(self.link_box)

        # buttons row
        btns = QtWidgets.QHBoxLayout()
        for text, slot in (
            ("➕ Add link", self._add_link),
            ("✏️ Edit", self._edit_selected),
            ("🗑 Delete", self._delete_selected),
            ("⬆️ Up", lambda: self._move(-1)),
            ("⬇️ Down", lambda: self._move(1)),
        ):
            b = QtWidgets.QPushButton(text)
            b.clicked.connect(slot)
            btns.addWidget(b)
        btns.addStretch()
        self.b_copy = QtWidgets.QPushButton("📋 Copy link")
        self.b_copy.setToolTip("Copy the full link of the selected connection")
        self.b_copy.clicked.connect(self._copy_link)
        btns.addWidget(self.b_copy)
        self.b_test = QtWidgets.QPushButton("🔍 Test all")
        self.b_test.clicked.connect(self._test_all)
        btns.addWidget(self.b_test)
        self.b_save = QtWidgets.QPushButton("💾 Save & restart service")
        self.b_save.setStyleSheet("font-weight: bold;")
        self.b_save.clicked.connect(self._save_and_restart)
        btns.addWidget(self.b_save)
        lay.addLayout(btns)

        self.status = QtWidgets.QStatusBar()
        self.setStatusBar(self.status)
        self._settings_action()
        self.status.showMessage("Ready.")

    def _settings_action(self):
        m = self.menuBar().addMenu("&Settings")
        a = QtGui.QAction("Testing & xray binary settings…", self)
        a.triggered.connect(self._open_settings)
        m.addAction(a)

    # ---------------- load & table ----------------
    def reload(self):
        try:
            config = config_io.load_config(self.path_edit.text().strip())
        except (OSError, json.JSONDecodeError) as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Could not read the config:\n{e}")
            return
        self.rows = []
        self._config = config
        for ob in config_io.user_outbounds(config):
            key = ob.get("_key") or (self._key_of(ob))
            ob["_key"] = key
            self.rows.append({"outbound": ob, "key": key,
                              "enabled": not self.state.is_disabled(key)})
        self.results.clear()
        self._pending.clear()
        self.b_test.setEnabled(True)
        self.b_test.setText("🔍 Test all")
        self._refresh_table()

    @staticmethod
    def _key_of(ob: dict) -> str:
        import uuid
        h = uuid.uuid5(uuid.NAMESPACE_URL, f"{ob['protocol']}|{json.dumps(ob.get('settings'), sort_keys=True)}")
        return str(h)[:8]

    def _refresh_table(self):
        self.table.setRowCount(len(self.rows))
        for i, row in enumerate(self.rows):
            ob, key = row["outbound"], row["key"]
            addr = _address_of(ob)
            ping = self.results.get(key)
            vals = [
                str(i + 1),
                self.state.display_name(ob),
                ob.get("protocol", "?"),
                addr,
                config_io.serving_ports(self._config, ob.get("tag", "")),
                ping["status"] if ping else ST_UNKNOWN,
                f"{ping['ping_ms']} ms" if ping and ping.get("ping_ms") is not None else "—",
            ]
            for c, v in enumerate(vals):
                item = QtWidgets.QTableWidgetItem(str(v))
                if c == COLS.index("Status"):
                    item.setForeground({"alive": QtGui.QColor("green"), "dead": QtGui.QColor("red"),
                                        "…": QtGui.QColor("orange")}.get(str(v), QtGui.QColor("gray")))
                    if ping and ping.get("error"):
                        item.setToolTip(ping["error"])
                if c == 0:
                    item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(i, c, item)
            chk = QtWidgets.QTableWidgetItem()
            chk.setFlags(QtCore.Qt.ItemFlag.ItemIsUserCheckable | QtCore.Qt.ItemFlag.ItemIsEnabled)
            chk.setCheckState(QtCore.Qt.CheckState.Checked if row["enabled"] else QtCore.Qt.CheckState.Unchecked)
            self.table.setItem(i, CHECK_COL, chk)
        # keep a valid selection; select row 0 if nothing is selected so the link box fills up
        if self.table.currentRow() < 0 and self.rows:
            self.table.selectRow(0)
        else:
            self._show_selected_link()

    def _on_item_changed(self, item: QtWidgets.QTableWidgetItem):
        if item.column() != CHECK_COL:
            return
        r = item.row()
        self.rows[r]["enabled"] = item.checkState() == QtCore.Qt.CheckState.Checked
        self.state.set_disabled(self.rows[r]["key"], not self.rows[r]["enabled"])

    # ---------------- actions ----------------
    def _selected_row(self) -> int:
        idx = self.table.currentRow()
        return idx

    def _add_link(self):
        text, ok = QtWidgets.QInputDialog.getMultiLineText(
            self, "Add link", "Paste a share link (vless/vmess/trojan/ss)\n(multiple links on separate lines are fine):")
        if not ok or not text.strip():
            return
        added, errors = 0, []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ob = link_parser.parse_link(line)
            except ValueError as e:
                errors.append(str(e))
                continue
            ob["_key"] = self._key_of(ob)
            self.rows.append({"outbound": ob, "key": ob["_key"],
                              "enabled": not self.state.is_disabled(ob["_key"])})
            added += 1
        if errors:
            QtWidgets.QMessageBox.warning(self, "Error", "\n".join(errors))
        if added:
            self._refresh_table()
            self.status.showMessage(f"{added} connection(s) added — testing all…")
            self._test_all()  # auto-test when links change

    def _edit_selected(self):
        r = self._selected_row()
        if r < 0:
            return
        row = self.rows[r]
        cur = self.state.display_name(row["outbound"])
        name, ok = QtWidgets.QInputDialog.getText(self, "Edit name", "Connection name:", text=cur)
        if ok and name.strip():
            self.state.set_name(row["key"], name.strip())
            self._refresh_table()
        # show the current link for copying
        link = link_parser.to_link(row["outbound"])
        if link:
            QtWidgets.QMessageBox.information(self, "Current link", link)

    def _delete_selected(self):
        r = self._selected_row()
        if r < 0:
            return
        if QtWidgets.QMessageBox.question(self, "Delete", f"Delete '{self.state.display_name(self.rows[r]['outbound'])}'?"
                ) == QtWidgets.QMessageBox.StandardButton.Yes:
            del self.rows[r]
            self._refresh_table()

    def _move(self, delta: int):
        r = self._selected_row()
        if r < 0 or not (0 <= r + delta < len(self.rows)):
            return
        self.rows[r], self.rows[r + delta] = self.rows[r + delta], self.rows[r]
        self._refresh_table()
        self.table.selectRow(r + delta)

    # ---------------- testing ----------------
    def _test_all(self, only_selected: bool = False):
        xbin = config_io.find_xray(self.state.data["xray_binary"])
        if not xbin:
            QtWidgets.QMessageBox.critical(self, "Error", "xray binary not found. Set its path in Settings.")
            return
        rows = [self._selected_row()] if only_selected and self._selected_row() >= 0 else range(len(self.rows))
        self._pending = {self.rows[r]["key"] for r in rows}
        for r in rows:
            key = self.rows[r]["key"]
            self.results[key] = {"status": ST_CHECKING, "ping_ms": None, "error": ""}
            w = TestWorker(key, xbin, self.rows[r]["outbound"],
                           self.state.data["test_url"], int(self.state.data["test_timeout"]))
            w.sig.done.connect(self._on_test_done)
            self.pool.start(w)
        self._refresh_table()
        self.b_test.setEnabled(False)
        self.b_test.setText(f"⏳ Testing… ({len(self._pending)})")
        self.status.showMessage(f"Test in progress: 0/{len(self._pending)}")

    def _test_progress_message(self) -> str:
        alive = sum(1 for r in self.results.values() if r.get("ok"))
        done = len(self.results) - sum(1 for r in self.results.values() if r.get("status") == ST_CHECKING)
        return f"Test in progress: {done} done ({alive} alive)"

    def _on_test_done(self, key: str, result: dict):
        result["status"] = ST_ALIVE if result["ok"] else ST_DEAD
        self.results[key] = result
        self._pending.discard(key)
        self._refresh_table()
        if self._pending:
            remaining = len(self._pending)
            self.b_test.setText(f"⏳ Testing… ({remaining} left)")
            self.status.showMessage(self._test_progress_message())
        else:
            self.b_test.setEnabled(True)
            self.b_test.setText("🔍 Test all")
            alive = sum(1 for r in self.results.values() if r.get("ok"))
            dead = sum(1 for r in self.results.values() if r.get("status") == ST_DEAD)
            self.status.showMessage(f"✅ Test all finished — {alive} alive, {dead} dead")

    # ---------------- save & service ----------------
    def _save_and_restart(self):
        path = self.path_edit.text().strip()
        try:
            config = config_io.load_config(path)
        except (OSError, json.JSONDecodeError) as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Could not read the config:\n{e}")
            return
        enabled = [r["outbound"] for r in self.rows if r["enabled"]]
        new_cfg = config_io.build_config(config, enabled)
        b = config_io.backup_config(path)
        config_io.save_config(path, new_cfg)
        user_svc = config_io.is_user_config(path)
        ok, msg = config_io.service_action("restart", user=user_svc)
        svc_name = "user service" if user_svc else "system service"
        icon = QtWidgets.QMessageBox.Icon.Information if ok else QtWidgets.QMessageBox.Icon.Warning
        QtWidgets.QMessageBox(icon, "Saved" if ok else "Service error",
                              f"Config saved (backup: {b})\n{'Service restarted.' if ok else f'Failed to restart {svc_name}: ' + msg}",
                              QtWidgets.QMessageBox.StandardButton.Ok, self).exec()
        self._test_all()  # auto-test when the config changes
        self._refresh_service()

    def _refresh_service(self):
        user_svc = config_io.is_user_config(self.path_edit.text().strip())
        base = ["systemctl"] + (["--user"] if user_svc else [])
        try:
            r = subprocess.run(base + ["is-active", "xray"], capture_output=True, text=True, timeout=5)
            st = r.stdout.strip()
            name = "User service" if user_svc else "System service"
            mark = "🟢" if st == "active" else "🔴"
            self.lbl_service.setText(f"{name}: {mark} {st or 'unknown'}")
        except Exception:
            self.lbl_service.setText("Service: —")

    # ---------------- misc ----------------
    def _pick_config(self):
        f, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose config", self.path_edit.text(), "JSON (*.json)")
        if f:
            self.path_edit.setText(f)
            self._on_path_changed()

    def _on_path_changed(self):
        self.state.data["config_path"] = self.path_edit.text().strip()
        self.state.save()
        self.reload()

    def _context_menu(self, pos):
        menu = QtWidgets.QMenu(self)
        menu.addAction("Test this connection", lambda: self._test_all(True))
        menu.addAction("Copy link", self._copy_link)
        menu.addAction("Edit name", self._edit_selected)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _copy_link(self):
        link = self.link_box.toPlainText().strip()
        if link and not link.startswith("("):
            QtGui.QGuiApplication.clipboard().setText(link)
            self.status.showMessage("Link copied.")

    def _show_selected_link(self):
        r = self._selected_row()
        if r < 0:
            self.link_box.setPlainText("")
            return
        link = link_parser.to_link(self.rows[r]["outbound"])
        if link:
            self.link_box.setPlainText(link)
        else:
            self.link_box.setPlainText("(no standard link can be built for this connection — see the config for details)")

    def _open_settings(self):
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Settings")
        form = QtWidgets.QFormLayout(dlg)
        e_bin = QtWidgets.QLineEdit(self.state.data["xray_binary"] or config_io.find_xray())
        e_url = QtWidgets.QLineEdit(self.state.data["test_url"])
        s_to = QtWidgets.QSpinBox()
        s_to.setRange(2, 60)
        s_to.setValue(int(self.state.data["test_timeout"]))
        form.addRow("xray binary:", e_bin)
        form.addRow("Test URL:", e_url)
        form.addRow("Test timeout (s):", s_to)
        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok
                                        | QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(dlg.accept)
        bb.rejected.connect(dlg.reject)
        form.addRow(bb)
        if dlg.exec():
            self.state.data.update({"xray_binary": e_bin.text().strip(), "test_url": e_url.text().strip(),
                                    "test_timeout": s_to.value()})
            self.state.save()


def main():
    app = QtWidgets.QApplication([])
    win = MainWindow()
    win.show()
    app.exec()
