from PyQt5.QtWidgets import (
     QTableWidget, QTableWidgetItem,  QHeaderView
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, pyqtSignal


class MemoryTableWidget(QTableWidget):
    BYTE_VIEW_MODE = 'byte'
    INT_VIEW_MODE = 'int'
    memoryUpdated = pyqtSignal()

    def __init__(self, mode='byte', change_callback=None):
        super().__init__()
        self.memory = bytearray()
        self.start_address = 0
        self.change_callback = change_callback
        self.setFont(QFont('Courier', 10))
        self.mode = mode

        if self.mode not in (self.BYTE_VIEW_MODE, self.INT_VIEW_MODE):
            raise ValueError("Invalid mode. Use 'byte' or 'int'.")

        self.horizontalHeader().hide()
        self.verticalHeader().hide()
        self.cellChanged.connect(self.handle_cell_change)
        # 连接信号到槽
        self.memoryUpdated.connect(self.on_memory_updated)

    def update_memory(self, start_address, memory):
        self.start_address = start_address
        self.memory = memory
        self.memoryUpdated.emit()

    def on_memory_updated(self):
        # 根据当前模式更新视图
        if self.mode == self.BYTE_VIEW_MODE:
            self.show_byte_view()
        elif self.mode == self.INT_VIEW_MODE:
            self.show_int_view()

    def show_byte_view(self):
        self.cellChanged.disconnect(self.handle_cell_change)

        # 清空表格
        self.clear()

        self.setColumnCount(18)
        self.setHorizontalHeaderLabels(['Address'] + [f'{i:02X}' for i in range(16)] + ['ASCII'])
        self.setRowCount(len(self.memory) // 16 + (1 if len(self.memory) % 16 else 0))
        self.setShowGrid(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        for row in range(self.rowCount()):
            address_item = QTableWidgetItem(f'{self.start_address + row * 16:016X}')
            address_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            self.setItem(row, 0, address_item)

            ascii_representation = ''
            for col in range(16):
                index = row * 16 + col
                if index < len(self.memory):
                    byte_value = self.memory[index]
                    hex_item = QTableWidgetItem(f'{byte_value:02X}')
                    self.setItem(row, col + 1, hex_item)
                    ascii_representation += chr(byte_value) if 32 <= byte_value <= 126 else '.'
                else:
                    hex_item = QTableWidgetItem('')
                    self.setItem(row, col + 1, hex_item)
                    ascii_representation += ' '

            ascii_item = QTableWidgetItem(ascii_representation)
            ascii_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            self.setItem(row, 17, ascii_item)

        self.cellChanged.connect(self.handle_cell_change)

    def show_int_view(self):
        self.cellChanged.disconnect(self.handle_cell_change)

        # 清空表格
        self.clear()

        self.setColumnCount(2)
        self.setHorizontalHeaderLabels(['Address', '8-Byte Int'])
        self.setRowCount(len(self.memory) // 8 + (1 if len(self.memory) % 8 else 0))
        self.setShowGrid(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        for row in range(self.rowCount()):
            address_item = QTableWidgetItem(f'{self.start_address + row * 8:016X}')
            address_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            self.setItem(row, 0, address_item)

            index = row * 8
            if index + 8 <= len(self.memory):
                int_value = int.from_bytes(self.memory[index:index+8], byteorder='little', signed=False)
                int_item = QTableWidgetItem(f'{int_value:016X}')
                self.setItem(row, 1, int_item)
            else:
                int_item = QTableWidgetItem('')
                self.setItem(row, 1, int_item)

        self.cellChanged.connect(self.handle_cell_change)

    def handle_cell_change(self, row, column):
        if column > 0:  # Only consider data cells
            if self.mode == self.BYTE_VIEW_MODE:  # Byte view
                index = row * 16 + (column - 1)
                try:
                    new_value_str = self.item(row, column).text()
                    new_value = int(new_value_str, 16)
                    if not (0 <= new_value <= 255):
                        raise ValueError("Byte value out of range")

                    self.memory[index] = new_value
                    actual_address = self.start_address + index
                    if self.change_callback:
                        self.change_callback(actual_address, new_value_str,0)
                except ValueError:
                    self.blockSignals(True)
                    original_value = self.memory[index]
                    self.item(row, column).setText(f'{original_value:02X}')
                    self.blockSignals(False)

            elif self.mode == self.INT_VIEW_MODE:  # Int view
                index = row * 8
                try:
                    new_value_str = self.item(row, column).text()
                    new_value = int(new_value_str, 16)
                    if index + 8 > len(self.memory):
                        raise ValueError("Index out of range")

                    self.memory[index:index+8] = new_value.to_bytes(8, byteorder='little')
                    actual_address = self.start_address + index
                    if self.change_callback:
                        self.change_callback(actual_address, new_value_str,1)
                except ValueError:
                    self.blockSignals(True)
                    original_value = int.from_bytes(self.memory[index:index+8], byteorder='little', signed=False)
                    self.item(row, column).setText(f'{original_value:016X}')
                    self.blockSignals(False)
