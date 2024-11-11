from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QHeaderView
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtCore import pyqtSignal, pyqtSlot, Qt

class RegisterTableWidget(QWidget):
    # Signal to notify when a register value is changed
    registerChanged = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()

        # Create a QTableWidget
        self.tableWidget = QTableWidget()
        self.tableWidget.setColumnCount(2)

        # Hide headers
        self.tableWidget.horizontalHeader().hide()
        self.tableWidget.verticalHeader().hide()

        # Hide grid lines
        self.tableWidget.setShowGrid(False)

        # Connect signals
        self.tableWidget.itemChanged.connect(self.on_item_changed)

        # Set layout
        layout = QVBoxLayout()
        layout.addWidget(self.tableWidget)
        self.setLayout(layout)

    def set_registers(self, registers):
        self.tableWidget.itemChanged.disconnect(self.on_item_changed)
        self.registers = registers
        self.tableWidget.setRowCount(0)
        self.tableWidget.setRowCount(len(registers))

        # Populate the table with data
        for row, (reg, val) in enumerate(registers.items()):
            reg_item = QTableWidgetItem(reg)
            reg_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)  # Make name read-only

            val_item = QTableWidgetItem(f"{val:016X}")  # Format as hexadecimal
            val_item.setForeground(QColor('black'))

            # Set font to bold for register name
            font = QFont()
            font.setBold(True)
            reg_item.setFont(font)

            reg_item.setForeground(QColor('black'))

            self.tableWidget.setItem(row, 0, reg_item)
            self.tableWidget.setItem(row, 1, val_item)

        # Adjust column widths
        self.tableWidget.setColumnWidth(0, 50)
        self.tableWidget.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tableWidget.update()
        self.tableWidget.itemChanged.connect(self.on_item_changed)

    @pyqtSlot(QTableWidgetItem)
    def on_item_changed(self, item):
        # Ensure that only the value column is editable
        if item.column() == 1:
            reg_name = self.tableWidget.item(item.row(), 0).text()
            try:
                # Convert the text back to an integer
                new_value = int(item.text(), 16)
                self.registers[reg_name] = new_value
                self.tableWidget.item(item.row(), 1).setText(f"{new_value:016X}")
                # 传递字符串，因为测试发现8字节传递不了，只能传送低4字节
                self.registerChanged.emit(reg_name, item.text())
            except ValueError:
                # Handle invalid input gracefully
                item.setText(f"{self.registers[reg_name]:016X}")

    def get_registers(self):
        return self.registers
