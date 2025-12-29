# wireshark_like.py
"""
Mini Wireshark-like GUI using PyQt5 + Scapy
Features:
 - Interface selection (Windows: uses scapy.arch.windows.get_windows_if_list)
 - BPF filter input
 - Start / Stop capture
 - Live table of packets (No, Time, Proto, Src, Dst, Len)
 - Packet details pane (packet.show() text)
 - Save captured packets to pcap (optional)
"""

import sys
import time
import threading
from datetime import datetime
from queue import Queue, Empty

from scapy.all import sniff, IP, TCP, UDP, Raw, conf
from scapy.utils import PcapWriter

# Windows helper for friendly iface listing (only available on Windows scapy distribution)
try:
    from scapy.arch.windows import get_windows_if_list
except Exception:
    get_windows_if_list = None

from PyQt5 import QtCore, QtWidgets, QtGui

# ---------- Capture thread (produces packets into a Queue) ----------
class SnifferThread(QtCore.QThread):
    packet_caught = QtCore.pyqtSignal(object)  # emits scapy packet

    def __init__(self, iface=None, bpf_filter=None, store_pcap=False, pcap_path="capture.pcap"):
        super().__init__()
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._stop_event = threading.Event()
        self.store_pcap = store_pcap
        self.pcap_path = pcap_path
        self.pcap_writer = None
        if self.store_pcap:
            self.pcap_writer = PcapWriter(self.pcap_path, append=True, sync=True)

    def run(self):
        # Using scapy sniff in a thread. sniff will call our callback for each packet.
        def _pkt_cb(pkt):
            if self._stop_event.is_set():
                return True  # stop?
            # write pcap if enabled
            if self.pcap_writer:
                try:
                    self.pcap_writer.write(pkt)
                except Exception:
                    pass
            # emit to GUI via Qt signal
            self.packet_caught.emit(pkt)

        try:
            sniff(iface=self.iface, prn=_pkt_cb, filter=self.bpf_filter, store=False, stop_filter=lambda x: self._stop_event.is_set())
        except Exception as e:
            # emit an error packet-like object (pass exception)
            self.packet_caught.emit(("__error__", str(e)))

    def stop(self):
        self._stop_event.set()
        # sniff stop_filter will check event and exit; wait a bit then quit
        if self.pcap_writer:
            try:
                self.pcap_writer.close()
            except Exception:
                pass
        self.wait(1000)


# ---------- Main Application GUI ----------
class MiniWireshark(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mini-Wireshark (Scapy + PyQt5)")
        self.resize(1000, 600)
        self.sniffer = None
        self.packet_count = 0
        self.captured_packets = []  # store packet refs if needed (caution memory)
        self.setup_ui()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # Top controls
        top_row = QtWidgets.QHBoxLayout()
        self.iface_combo = QtWidgets.QComboBox()
        self.refresh_ifaces_btn = QtWidgets.QPushButton("Refresh Interfaces")
        self.filter_input = QtWidgets.QLineEdit()
        self.filter_input.setPlaceholderText("BPF filter (e.g. tcp, port 80, icmp) — leave empty for all")
        self.start_btn = QtWidgets.QPushButton("Start")
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.save_pcap_chk = QtWidgets.QCheckBox("Save to pcap (capture.pcap)")

        top_row.addWidget(QtWidgets.QLabel("Interface:"))
        top_row.addWidget(self.iface_combo)
        top_row.addWidget(self.refresh_ifaces_btn)
        top_row.addWidget(QtWidgets.QLabel("Filter:"))
        top_row.addWidget(self.filter_input)
        top_row.addWidget(self.save_pcap_chk)
        top_row.addWidget(self.start_btn)
        top_row.addWidget(self.stop_btn)

        layout.addLayout(top_row)

        # Packet table and details
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        # Table
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["No", "Time", "Proto", "Source", "Destination", "Len"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # Details text
        self.details = QtWidgets.QPlainTextEdit()
        self.details.setReadOnly(True)

        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

        # Status bar / bottom
        bottom_row = QtWidgets.QHBoxLayout()
        self.status_label = QtWidgets.QLabel("Ready.")
        bottom_row.addWidget(self.status_label)
        layout.addLayout(bottom_row)

        # signals
        self.refresh_ifaces_btn.clicked.connect(self.populate_interfaces)
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.table.itemSelectionChanged.connect(self.on_table_selection_change)

        # initial populate
        self.populate_interfaces()

    def populate_interfaces(self):
        self.iface_combo.clear()
        if get_windows_if_list:  # Windows: list returns dicts with 'name' & 'description'
            ifaces = get_windows_if_list()
            # prefer Wi-Fi or Ethernet friendly names when present; show description as tooltip
            for iface in ifaces:
                name = iface.get("name")
                desc = iface.get("description") or ""
                display = name
                self.iface_combo.addItem(display, userData=(name, desc))
                idx = self.iface_combo.count()-1
                self.iface_combo.setItemData(idx, desc, QtCore.Qt.ToolTipRole)
        else:
            # fallback: use scapy conf.iface
            self.iface_combo.addItem(conf.iface, userData=(conf.iface, "default"))

    def start_capture(self):
        iface_data = self.iface_combo.currentData()
        iface = iface_data[0] if iface_data else None
        bpf = self.filter_input.text().strip() or None
        save_pcap = self.save_pcap_chk.isChecked()
        pcap_path = "capture.pcap"

        # ensure admin privileges note (we just set status)
        self.status_label.setText(f"Starting on {iface} (filter={bpf}) — if nothing appears, run with Admin/Npcap installed.")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.table.setRowCount(0)
        self.packet_count = 0
        self.captured_packets.clear()

        # start thread
        self.sniffer = SnifferThread(iface=iface, bpf_filter=bpf, store_pcap=save_pcap, pcap_path=pcap_path)
        self.sniffer.packet_caught.connect(self.on_packet_caught)
        self.sniffer.start()

    def stop_capture(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Stopped.")

    def on_packet_caught(self, pkt):
        # handle error emitted as tuple
        if isinstance(pkt, tuple) and pkt and pkt[0] == "__error__":
            self.status_label.setText(f"Sniffer error: {pkt[1]}")
            return

        # Increment count, add table row
        self.packet_count += 1
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        proto = "OTHER"
        src = "-"
        dst = "-"
        length = len(pkt) if hasattr(pkt, "__len__") else 0

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            if pkt.haslayer(TCP):
                proto = "TCP"
            elif pkt.haslayer(UDP):
                proto = "UDP"
            else:
                proto = pkt[IP].proto if hasattr(pkt[IP], "proto") else "IP"

        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(self.packet_count)))
        self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(ts))
        self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(proto))
        self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(src)))
        self.table.setItem(row, 4, QtWidgets.QTableWidgetItem(str(dst)))
        self.table.setItem(row, 5, QtWidgets.QTableWidgetItem(str(length)))

        # keep packet reference (optional)
        self.captured_packets.append(pkt)

        # auto-scroll to bottom
        self.table.scrollToBottom()
        self.status_label.setText(f"Captured: {self.packet_count}")

    def on_table_selection_change(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        pkt = self.captured_packets[row]
        # show detailed info using show() -> string
        try:
            s = []
            pkt.show(dump=True)  # this prints; instead capture string
            # scapy's show() returns None; use built-in method to get summary + layers
            s.append(pkt.summary())
            for layer in pkt.layers():
                s.append(str(layer))
                try:
                    s.append(str(layer.__dict__))
                except Exception:
                    pass
        except Exception:
            s = [repr(pkt)]
        self.details.setPlainText("\n".join(s))


# ---------- Run ----------
def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MiniWireshark()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
# ---------- End of File ----------