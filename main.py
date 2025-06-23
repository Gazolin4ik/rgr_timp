import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QMessageBox, QInputDialog, QHBoxLayout, QLabel, QComboBox, QDialog, QLineEdit, QFormLayout
)
from db import save_scan_to_db, get_scan_history, get_access_points, get_access_points_by_scan, check_user_credentials
from wifi_scanner import scan_wifi

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Вход для персонала")
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        layout = QFormLayout()
        layout.addRow("Логин:", self.username)
        layout.addRow("Пароль:", self.password)
        self.login_btn = QPushButton("Войти")
        self.login_btn.clicked.connect(self.accept)
        layout.addWidget(self.login_btn)
        self.setLayout(layout)
    def get_credentials(self):
        return self.username.text(), self.password.text()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Мониторинг Wi-Fi сетей")
        self.resize(900, 600)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "SSID", "BSSID", "Сигнал", "Канал", "Шифрование", "Открытая", "Подозрительная"
        ])
        self.scan_btn = QPushButton("Сканировать Wi-Fi")
        self.scan_btn.clicked.connect(self.scan_wifi)
        self.history_btn = QPushButton("История сканирований")
        self.history_btn.clicked.connect(self.show_history)
        self.filter_open = QComboBox()
        self.filter_open.addItems(["Все", "Только открытые", "Только защищённые"])
        self.filter_open.currentIndexChanged.connect(self.update_table)
        self.filter_susp = QComboBox()
        self.filter_susp.addItems(["Все", "Только подозрительные", "Только обычные"])
        self.filter_susp.currentIndexChanged.connect(self.update_table)
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Фильтр открытых:"))
        filter_layout.addWidget(self.filter_open)
        filter_layout.addWidget(QLabel("Фильтр подозрительных:"))
        filter_layout.addWidget(self.filter_susp)
        layout = QVBoxLayout()
        layout.addLayout(filter_layout)
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.history_btn)
        layout.addWidget(self.table)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        self.update_table()

    def scan_wifi(self):
        try:
            aps = scan_wifi()
            save_scan_to_db(aps)
            QMessageBox.information(self, "Готово", "Сканирование завершено и данные сохранены в истории.")
            self.update_table()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def update_table(self):
        filter_open = self.filter_open.currentIndex()
        filter_susp = self.filter_susp.currentIndex()
        open_val = None if filter_open == 0 else (filter_open == 1)
        susp_val = None if filter_susp == 0 else (filter_susp == 1)
        aps = get_access_points(filter_open=open_val, filter_suspicious=susp_val)
        self.table.setRowCount(len(aps))
        for row, ap in enumerate(aps):
            self.table.setItem(row, 0, QTableWidgetItem(ap.get("ssid") or ""))
            self.table.setItem(row, 1, QTableWidgetItem(ap.get("bssid") or ""))
            self.table.setItem(row, 2, QTableWidgetItem(str(ap.get("signal_strength") or "")))
            self.table.setItem(row, 3, QTableWidgetItem(str(ap.get("channel") or "")))
            self.table.setItem(row, 4, QTableWidgetItem(ap.get("encryption") or ""))
            self.table.setItem(row, 5, QTableWidgetItem("Да" if ap["is_open"] else "Нет"))
            self.table.setItem(row, 6, QTableWidgetItem("Да" if ap["is_suspicious"] else "Нет"))

    def show_history(self):
        history = get_scan_history()
        dlg = QDialog(self)
        dlg.setWindowTitle("История сканирований")
        table = QTableWidget(len(history), 5)
        table.setHorizontalHeaderLabels(["Дата/время", "Всего", "Открытых", "Подозрительных", "Подробнее"])
        for row, h in enumerate(history):
            table.setItem(row, 0, QTableWidgetItem(str(h['scan_time'])))
            table.setItem(row, 1, QTableWidgetItem(str(h['total_found'])))
            table.setItem(row, 2, QTableWidgetItem(str(h['open_found'])))
            table.setItem(row, 3, QTableWidgetItem(str(h['suspicious_found'])))
            btn = QPushButton("Показать")
            btn.clicked.connect(lambda _, scan_id=h['id']: self.show_scan_details(scan_id))
            table.setCellWidget(row, 4, btn)
        layout = QVBoxLayout()
        layout.addWidget(table)
        dlg.setLayout(layout)
        dlg.resize(600, 400)
        dlg.exec_()

    def show_scan_details(self, scan_id):
        aps = get_access_points_by_scan(scan_id)
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Точки для сканирования {scan_id}")
        table = QTableWidget(len(aps), 7)
        table.setHorizontalHeaderLabels([
            "SSID", "BSSID", "Сигнал", "Канал", "Шифрование", "Открытая", "Подозрительная"
        ])
        for row, ap in enumerate(aps):
            table.setItem(row, 0, QTableWidgetItem(ap.get("ssid") or ""))
            table.setItem(row, 1, QTableWidgetItem(ap.get("bssid") or ""))
            table.setItem(row, 2, QTableWidgetItem(str(ap.get("signal_strength") or "")))
            table.setItem(row, 3, QTableWidgetItem(str(ap.get("channel") or "")))
            table.setItem(row, 4, QTableWidgetItem(ap.get("encryption") or ""))
            table.setItem(row, 5, QTableWidgetItem("Да" if ap["is_open"] else "Нет"))
            table.setItem(row, 6, QTableWidgetItem("Да" if ap["is_suspicious"] else "Нет"))
        layout = QVBoxLayout()
        layout.addWidget(table)
        dlg.setLayout(layout)
        dlg.resize(800, 400)
        dlg.exec_()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Окно входа
    while True:
        login = LoginDialog()
        if login.exec_() == QDialog.Accepted:
            username, password = login.get_credentials()
            if check_user_credentials(username, password):
                break
            else:
                QMessageBox.warning(None, "Ошибка входа", "Неверный логин или пароль!")
        else:
            sys.exit(0)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_()) 