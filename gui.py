
import sys, json, sqlite3
from pathlib import Path
from PySide6.QtWidgets import (
    QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QFormLayout,
    QLineEdit,QPushButton,QTabWidget,QPlainTextEdit,QLabel,QSpinBox,
    QFileDialog,QProgressBar,QTableWidget,QTableWidgetItem
)
from PySide6.QtCore import Qt, QProcess, QUrl
from PySide6.QtGui import QDesktopServices

CONFIG = Path("config.json")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Deja Vuln")
        self.resize(900,650)

        tabs=QTabWidget()
        self.setCentralWidget(tabs)

        # Settings tab
        settings=QWidget(); f=QFormLayout(settings)
        self.qurl=QLineEdit()
        self.quser=QLineEdit()
        self.qpass=QLineEdit(); self.qpass.setEchoMode(QLineEdit.Password)
        self.taccess=QLineEdit(); self.taccess.setEchoMode(QLineEdit.Password)
        self.tsecret=QLineEdit(); self.tsecret.setEchoMode(QLineEdit.Password)

        self.clean_days = QSpinBox()
        self.clean_days.setRange(1, 365)
        self.clean_days.setValue(365)
        self.clean_days.setSuffix(" days")

        f.addRow("Qualys URL", self.qurl)
        f.addRow("Qualys Username", self.quser)
        f.addRow("Qualys Password", self.qpass)

        f.addRow("Tenable Access Key", self.taccess)
        f.addRow("Tenable Secret Key", self.tsecret)

        f.addRow("Delete Historical Data in ", self.clean_days)

        save=QPushButton("Save Configuration")
        save.clicked.connect(self.save_config)
        f.addRow(save)
        tabs.addTab(settings,"Settings")

        # Export tab
        export=QWidget(); v=QVBoxLayout(export)
        self.pb=QProgressBar()
        self.log=QPlainTextEdit(); self.log.setReadOnly(True)
        bq=QPushButton("Run Qualys Export")
        bt=QPushButton("Run Tenable Export")
        ba=QPushButton("Run Trend Analysis")
        bq.clicked.connect(lambda:self.run_script("scripts.qualys_export"))
        bt.clicked.connect(lambda:self.run_script("scripts.tenable_export"))
        ba.clicked.connect(lambda:self.run_script("scripts.data_analysis"))
        v.addWidget(bq);v.addWidget(bt);v.addWidget(ba)
        # Cancel button to stop a running script
        bc=QPushButton("Cancel Running Script")
        bc.setEnabled(False)
        bc.clicked.connect(self.cancel_script)
        v.addWidget(bc)
        # track buttons and process
        self.run_buttons = [bq, bt, ba]
        self.cancel_btn = bc
        self.current_proc = None
        v.addWidget(self.pb);v.addWidget(self.log)
        tabs.addTab(export,"Data Collection")

        # Dashboard tab
        dash=QWidget(); dv=QVBoxLayout(dash)
        self.limit=QSpinBox()
        self.limit.setRange(1,100000)
        self.limit.setValue(5000)
        dv.addWidget(QLabel("Top vulnerability transitions (1-100,000):"))
        dv.addWidget(self.limit)
        # Table view for dashboard results
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Vuln ID", "Plugin", "Transitions", "Last Transition"])
        dv.addWidget(self.table)
        gen=QPushButton("Generate Dashboard")
        gen.clicked.connect(self.generate_dashboard)
        dv.addWidget(gen)

        openbtn=QPushButton("Open Data Folder")
        openbtn.clicked.connect(self.open_hist)
        dv.addWidget(openbtn)
        tabs.addTab(dash,"Dashboard")

        self.load_config()

    def save_config(self):
        CONFIG.write_text(json.dumps({
            "qualys_url": self.qurl.text(),
            "qualys_username": self.quser.text(),
            "qualys_password": self.qpass.text(),

            "tenable_access": self.taccess.text(),
            "tenable_secret": self.tsecret.text(),

            "history_retention_days": self.clean_days.value()
        }, indent=4))
        self.log.appendPlainText("Configuration saved.")

    def load_config(self):
        if not CONFIG.exists():
            return

        d = json.loads(CONFIG.read_text())

        self.qurl.setText(d.get("qualys_url", ""))
        self.quser.setText(d.get("qualys_username", ""))
        self.qpass.setText(d.get("qualys_password", ""))

        self.taccess.setText(d.get("tenable_access", ""))
        self.tsecret.setText(d.get("tenable_secret", ""))

        self.clean_days.setValue(
            d.get("history_retention_days", 365)
        )

    def run_script(self, module, args=None):
        self.log.appendPlainText(f"Starting: {module}")
        self.pb.setRange(0,0)  # busy indicator
        # disable run buttons + enable cancel
        for b in self.run_buttons:
            b.setEnabled(False)
        self.cancel_btn.setEnabled(True)

        self.current_proc = QProcess(self)
        self.current_proc.setProgram(sys.executable)
        arg_list = ["-m", module]
        if args:
            # args should be list of strings
            arg_list += list(args)
        self.current_proc.setArguments(arg_list)
        self.current_proc.setWorkingDirectory(str(Path.cwd()))

        self.current_proc.readyReadStandardOutput.connect(lambda p=self.current_proc: self.log.appendPlainText(p.readAllStandardOutput().data().decode()))
        self.current_proc.readyReadStandardError.connect(lambda p=self.current_proc: self.log.appendPlainText(p.readAllStandardError().data().decode()))
        self.current_proc.finished.connect(lambda exitCode, exitStatus, p=self.current_proc, m=module: self._on_process_finished(p, m, exitCode, exitStatus))

        self.current_proc.start()

    def cancel_script(self):
        if not getattr(self, 'current_proc', None):
            self.log.appendPlainText("No running process to cancel.")
            return
        state = self.current_proc.state()
        # QProcess.NotRunning == 0
        if state != QProcess.NotRunning:
            self.log.appendPlainText("Terminating running process...")
            self.current_proc.terminate()
            # also ensure UI reflects stop request
            self.pb.setRange(0,100)
            self.pb.setValue(0)
            self.cancel_btn.setEnabled(False)
        else:
            self.log.appendPlainText("Process already stopped.")


    def generate_dashboard(self):
        limit = int(self.limit.value())
        self.log.appendPlainText(f"Generating dashboard (top {limit})...")
        db_path = Path("data/transition_history.db")
        if not db_path.exists():
            self.log.appendPlainText(f"History DB not found: {db_path}")
            # clear table
            self.table.setRowCount(0)
            return
        try:
            con = sqlite3.connect(str(db_path))
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('vuln_stats','transitions')")
            tables = [r[0] for r in cur.fetchall()]
            results = []
            if 'vuln_stats' in tables:
                cur.execute(
                    "SELECT vuln_id, plugin_name, transition_count, last_transition_type FROM vuln_stats ORDER BY transition_count DESC, vuln_id DESC LIMIT ?",
                    (limit,)
                )
                results = cur.fetchall()
                if not results:
                    self.log.appendPlainText('No rows in vuln_stats table.')
                    self.table.setRowCount(0)
                else:
                    self.table.setRowCount(len(results))
                    for i, row in enumerate(results, start=0):
                        vid, plugin_name, cnt, last_type = row
                        self.table.setItem(i, 0, QTableWidgetItem(str(vid)))
                        self.table.setItem(i, 1, QTableWidgetItem(str(plugin_name) if plugin_name is not None else ""))
                        self.table.setItem(i, 2, QTableWidgetItem(str(cnt)))
                        self.table.setItem(i, 3, QTableWidgetItem(str(last_type) if last_type is not None else ""))
                        self.log.appendPlainText(f"{i+1}. {vid} — transitions={cnt} — plugin_name={plugin_name} — last={last_type}")
                    con.close()
                    return

            if 'transitions' in tables:
                cur.execute(
                    "SELECT vuln_id, COUNT(*) as cnt FROM transitions GROUP BY vuln_id ORDER BY cnt DESC, vuln_id DESC LIMIT ?",
                    (limit,)
                )
                results = cur.fetchall()
                if not results:
                    self.log.appendPlainText('No rows in transitions table.')
                    self.table.setRowCount(0)
                else:
                    self.table.setRowCount(len(results))
                    for i, row in enumerate(results, start=0):
                        vid, cnt = row
                        self.table.setItem(i, 0, QTableWidgetItem(str(vid)))
                        self.table.setItem(i, 1, QTableWidgetItem(""))
                        self.table.setItem(i, 2, QTableWidgetItem(str(cnt)))
                        self.table.setItem(i, 3, QTableWidgetItem(""))
                        self.log.appendPlainText(f"{i+1}. {vid} — transitions={cnt}")
                    con.close()
                    return

            self.log.appendPlainText("No suitable tables found in history DB.")
            con.close()
        except Exception as e:
            self.log.appendPlainText(f"Failed to query history DB: {e}")

    def _on_process_finished(self, proc, module, exitCode, exitStatus):
        self.pb.setRange(0,100)
        self.pb.setValue(100)
        self.log.appendPlainText(f"{module} finished with exit code {exitCode}")
        # re-enable run buttons + disable cancel
        for b in getattr(self, 'run_buttons', []):
            b.setEnabled(True)
        if hasattr(self, 'cancel_btn'):
            self.cancel_btn.setEnabled(False)
        self.current_proc = None
        proc.deleteLater()

    def open_hist(self):
        if Path("data").exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path("data").resolve())))
            return
        self.log.appendPlainText("No HistoricalData directory found.")

app=QApplication(sys.argv)
w=MainWindow()
w.show()
app.exec()
