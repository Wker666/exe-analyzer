
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QStyledItemDelegate, QHeaderView, QStyle
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt, pyqtSignal, QEventLoop

# Global variables to track highlighted rows
highlighted_bp_rows = []  # List for general highlighted rows
cur_run_highlight_row = -1  # Single integer for special highlight

# Custom QTableWidgetItem classes for different purposes
class AddressItem(QTableWidgetItem):
    def __init__(self, text):
        super().__init__(text)
        self.setFlags(self.flags() & ~Qt.ItemIsEditable)  # Make non-editable

class BytecodeItem(QTableWidgetItem):
    def __init__(self, text):
        super().__init__(text)
        self.setTextAlignment(Qt.AlignLeft)  # Align text to the left
        self.setFlags(self.flags() & ~Qt.ItemIsEditable)  # Make non-editable

class InstructionItem(QTableWidgetItem):
    def __init__(self, instruction, operands):
        # Combine the instruction and operands into a single string
        super().__init__(f"{instruction} {operands}")
        self.instruction = instruction
        self.operands = operands
        # This item is editable by default

class CommentItem(QTableWidgetItem):
    def __init__(self, text):
        super().__init__(text)
        self.setFlags(self.flags() & ~Qt.ItemIsEditable)  # Make non-editable

# Custom delegate class
class InstructionDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        try:
            # Get the data object
            item = index.data(Qt.UserRole)
            # Determine if the row is highlighted
            global highlighted_bp_rows, cur_run_highlight_row
            if index.row() == cur_run_highlight_row:
                painter.fillRect(option.rect, QColor('lightblue'))  # Special highlight background
            elif index.row() in highlighted_bp_rows:
                painter.fillRect(option.rect, QColor('yellow'))  # General highlight background

            # Highlight selected rows
            if option.state & QStyle.State_Selected:
                painter.fillRect(option.rect, option.palette.highlight())

            if isinstance(item, InstructionItem):
                # Instruction type
                instruction = item.instruction
                operands = item.operands

                # Draw the instruction part
                painter.save()
                try:
                    painter.setPen(QColor('green'))
                    painter.drawText(option.rect, Qt.AlignLeft, instruction)
                finally:
                    painter.restore()

                # Draw the operands part
                if operands:
                    painter.save()
                    try:
                        painter.setPen(QColor('blue'))
                        metrics = painter.fontMetrics()
                        instruction_width = metrics.width(instruction + ' ')
                        painter.drawText(option.rect.adjusted(instruction_width, 0, 0, 0), Qt.AlignLeft, operands)
                    finally:
                        painter.restore()
            else:
                # Default drawing
                painter.save()
                try:
                    painter.setPen(QColor('black'))
                    painter.drawText(option.rect, Qt.AlignLeft, index.data())
                finally:
                    painter.restore()
        except Exception as e:
            print(f"Error in paint: {e}")

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        option.widget = None  # Prevent default drawing

class AssemblerTableWidget(QTableWidget):
    # Define a signal that will be emitted when instructions are set
    instructionsUpdated = pyqtSignal(list)
    updateCompleted = pyqtSignal()
    instructionsScrollToItem = pyqtSignal(int)

    def __init__(self, on_instruction_modified, parent=None):
        super().__init__(parent)

        self.load_assembly_loop = None

        self.setColumnCount(4)
        self.setHorizontalHeaderLabels(['Address', 'Bytecode', 'Instruction', 'Comment'])
        self.setItemDelegate(InstructionDelegate())  # Set custom delegate

        # Set column width to fit content
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.horizontalHeader().setStretchLastSection(True)

        # Remove grid lines and headers
        self.setShowGrid(False)
        self.horizontalHeader().hide()
        self.verticalHeader().hide()
        self.verticalHeader().setDefaultSectionSize(20)

        # Set the background color and font of the entire table
        # background - color:  # D2B48C;  /* Tan color */
        self.setStyleSheet("""
            QTableWidget {
                font-family: 'Microsoft YaHei';
                font-size: 8pt;
            }
        """)
        # Allow full row selection
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        # Connect itemChanged signal to a custom slot
        self.itemChanged.connect(self.handle_item_changed)
        # Save the callback function
        self.on_instruction_modified = on_instruction_modified

        # Connect the signal to a slot
        self.instructionsUpdated.connect(self.update_instructions)
        self.instructionsScrollToItem.connect(self.scroll_to_row)

    def set_instructions(self, instructions):
        self.load_assembly_loop = QEventLoop()
        self.updateCompleted.connect(self.load_assembly_loop.quit)
        self.instructionsUpdated.emit(instructions)
        self.load_assembly_loop.exec_()

    def update_instructions(self, instructions):

        self.itemChanged.disconnect(self.handle_item_changed)
        self.setUpdatesEnabled(False)  # Disable updates for better performance
        self.clearContents()  # Clear existing contents but keep headers

        self.setRowCount(len(instructions))

        for row, (address, bytecode, instruction, operands, comment) in enumerate(instructions):
            address_item = AddressItem(address)
            bytecode_item = BytecodeItem(bytecode)
            instruction_item = InstructionItem(instruction, operands)
            comment_item = CommentItem(comment)
            self.setItem(row, 0, address_item)
            self.setItem(row, 1, bytecode_item)
            self.setItem(row, 2, instruction_item)
            self.setItem(row, 3, comment_item)
            # Set UserRole data for each item, for the delegate to use
            self.item(row, 0).setData(Qt.UserRole, address_item)
            self.item(row, 1).setData(Qt.UserRole, bytecode_item)
            self.item(row, 2).setData(Qt.UserRole, instruction_item)
            self.item(row, 3).setData(Qt.UserRole, comment_item)
        self.setUpdatesEnabled(True)  # Re-enable updates
        self.viewport().update()  # Update the view
        self.itemChanged.connect(self.handle_item_changed)
        self.updateCompleted.emit()

    def handle_item_changed(self, item):
        # Check if the modified item is in the instruction column
        if isinstance(item, InstructionItem):
            row = item.row()
            # Call the provided callback function
            self.on_instruction_modified(int(self.item(row, 0).text(), 16), item.text())

    def clear_all_rows(self):
        self.setRowCount(0)

    def highlight_bp_row(self, row_number):
        global highlighted_bp_rows
        if 0 <= row_number < self.rowCount() and row_number not in highlighted_bp_rows:
            highlighted_bp_rows.append(row_number)
            self.viewport().update()  # Trigger a repaint of the table

    def set_cur_run_highlight(self, row_number):
        global cur_run_highlight_row
        if 0 <= row_number < self.rowCount():
            cur_run_highlight_row = row_number
            self.viewport().update()  # Trigger a repaint of the table

    def scroll_to_row(self, row):
        # 确保在主线程中执行
        self.scrollToItem(
            self.item(row, 0),
            QTableWidget.PositionAtTop
        )

    def clear_cur_run_highlight(self):
        global cur_run_highlight_row
        cur_run_highlight_row = -1
        self.viewport().update()  # Trigger a repaint of the table

    def clear_bp_highlight(self, row_number=None):
        global highlighted_bp_rows
        if row_number is None:
            highlighted_bp_rows.clear()  # Clear all highlights
        else:
            if row_number in highlighted_bp_rows:
                highlighted_bp_rows.remove(row_number)  # Remove specific highlight
        self.viewport().update()  # Trigger a repaint of the table
