# nmap_gui.py
"""
Simple Nmap GUI (PyQt5) that runs nmap as a subprocess and streams output.
Use only on authorized targets.
"""

import sys
import shutil
import subprocess
import threading
from PyQt5 import QtWidgets, QtCore, QtGui

# ---------- Helper: check nmap available ----------
def find_nmap():
    path = shutil.which("nmap")
    return path

# ---------- Worker thread to run nmap and stream output ----------
class NmapRunner(QtCore.QObject):
    output_line = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(int)   # exit code

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd
        self._proc = None
        self._stop_requested = False

    def run(self):
        try:
            # Start subprocess
            self._proc = subprocess.Popen(self.cmd,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT,
                                          universal_newlines=True,
                                          bufsize=1,
                                          shell=False)
            # stream output line by line
            for line in self._proc.stdout:
                if self._stop_requested:
                    try:
                        self._proc.terminate()
                    except Exception:
                        pass
                    break
                self.output_line.emit(line.rstrip("\n"))
            self._proc.wait()
            exit_code = self._proc.returncode or 0
            self.finished.emit(exit_code)
        except Exception as e:
            self.output_line.emit(f"[ERROR] {e}")
            self.finished.emit(-1)

    def stop(self):
        self._stop_requested = True
        try:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
        except Exception:
            pass

# ---------- Main GUI ----------
class NmapGUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nmap GUI - Mini Scanner")
        self.resize(900, 600)
        self._worker_thread = None
        self._runner = None
        self.setup_ui()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # Top form
        form = QtWidgets.QFormLayout()
        self.target_edit = QtWidgets.QLineEdit()
        self.target_edit.setPlaceholderText("Target (IP, domain, or CIDR) e.g. 192.168.1.1 or example.com")
        self.ports_edit = QtWidgets.QLineEdit()
        self.ports_edit.setPlaceholderText("Ports (e.g. 1-1000 or 80,443) — leave empty for default")
        self.flags_group = QtWidgets.QGroupBox("Scan options")
        flags_layout = QtWidgets.QHBoxLayout()
        self.chk_syn = QtWidgets.QCheckBox("-sS (SYN scan)")
        self.chk_version = QtWidgets.QCheckBox("-sV (Service/version)")
        self.chk_os = QtWidgets.QCheckBox("-O (OS detect)")
        self.chk_no_ping = QtWidgets.QCheckBox("-Pn (no ping)")
        self.timing_combo = QtWidgets.QComboBox()
        self.timing_combo.addItems(["T3 (default)", "T0 (paranoid)", "T1 (sneaky)", "T2 (polite)", "T4 (aggressive)", "T5 (insane)"])
        flags_layout.addWidget(self.chk_syn)
        flags_layout.addWidget(self.chk_version)
        flags_layout.addWidget(self.chk_os)
        flags_layout.addWidget(self.chk_no_ping)
        flags_layout.addWidget(QtWidgets.QLabel("Timing:"))
        flags_layout.addWidget(self.timing_combo)
        self.flags_group.setLayout(flags_layout)

        form.addRow("Target:", self.target_edit)
        form.addRow("Ports:", self.ports_edit)
        form.addRow(self.flags_group)
        layout.addLayout(form)

        # Buttons
        btn_row = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Start Scan")
        self.stop_btn = QtWidgets.QPushButton("Stop Scan")
        self.stop_btn.setEnabled(False)
        self.save_btn = QtWidgets.QPushButton("Save Output")
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addWidget(self.save_btn)
        layout.addLayout(btn_row)

        # Output text area
        self.output_txt = QtWidgets.QPlainTextEdit()
        self.output_txt.setReadOnly(True)
        font = QtGui.QFont("Consolas", 10)
        self.output_txt.setFont(font)
        layout.addWidget(self.output_txt)

        # status
        self.status_label = QtWidgets.QLabel("Ready. Make sure 'nmap' is installed and you have permission to scan.")
        layout.addWidget(self.status_label)

        # connect
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn.clicked.connect(self.on_stop)
        self.save_btn.clicked.connect(self.on_save)

    def validate_inputs(self):
        target = self.target_edit.text().strip()
        if not target:
            QtWidgets.QMessageBox.warning(self, "Input error", "Please provide a target to scan.")
            return None
        return target

    def build_command(self):
        # base
        cmd = [find_nmap()]
        # timing
        timing_text = self.timing_combo.currentText()
        if timing_text.startswith("T"):
            t = timing_text.split()[0]
            cmd.append(f"-{t}")
        # flags
        if self.chk_syn.isChecked():
            cmd.append("-sS")
        if self.chk_version.isChecked():
            cmd.append("-sV")
        if self.chk_os.isChecked():
            cmd.append("-O")
        if self.chk_no_ping.isChecked():
            cmd.append("-Pn")
        # ports
        ports = self.ports_edit.text().strip()
        if ports:
            cmd.extend(["-p", ports])
        # target
        cmd.append(self.target_edit.text().strip())
        return cmd

    def append_output(self, text):
        self.output_txt.appendPlainText(text)

    def on_start(self):
        nmap_path = find_nmap()
        if not nmap_path:
            QtWidgets.QMessageBox.critical(self, "nmap not found", "nmap binary not found in PATH. Install Nmap and restart.")
            return
        target = self.validate_inputs()
        if not target:
            return

        cmd = self.build_command()
        self.output_txt.clear()
        self.append_output(f"[+] Running: {' '.join(cmd)}\n")
        self.status_label.setText("Running scan...")

        # disable/enable
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        # start worker in thread
        self._runner = NmapRunner(cmd)
        self._runner.output_line.connect(self.append_output)
        self._runner.finished.connect(self.on_finished)

        self._worker_thread = QtCore.QThread()
        self._runner.moveToThread(self._worker_thread)
        self._worker_thread.started.connect(self._runner.run)
        self._worker_thread.start()

    def on_stop(self):
        if self._runner:
            self._runner.stop()
            self.status_label.setText("Stopping...")

    def on_finished(self, exit_code):
        self.status_label.setText(f"Scan finished (exit {exit_code}).")
        self.append_output(f"\n[+] Scan finished (exit code {exit_code})")
        # cleanup thread
        try:
            if self._worker_thread:
                self._worker_thread.quit()
                self._worker_thread.wait(2000)
        except Exception:
            pass
        self._runner = None
        self._worker_thread = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def on_save(self):
        text = self.output_txt.toPlainText()
        if not text.strip():
            QtWidgets.QMessageBox.information(self, "No output", "No output to save.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save scan output", "nmap_output.txt", "Text Files (*.txt);;All Files (*)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            QtWidgets.QMessageBox.information(self, "Saved", f"Saved output to {path}")

# ---------- run ----------
def main():
    app = QtWidgets.QApplication(sys.argv)
    # check nmap
    if not find_nmap():
        QtWidgets.QMessageBox.critical(None, "nmap missing", "nmap binary not found in PATH. Install Nmap first.")
        # still allow GUI open so user can install; comment next line if you prefer exiting.
        # sys.exit(1)
    gui = NmapGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
