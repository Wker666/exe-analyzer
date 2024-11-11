from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot


class SignalHandler(QObject):
    quit_signal = pyqtSignal()  # Signal to quit the application

    def __init__(self,  app):
        super().__init__()
        self.app = app
        self.quit_signal.connect(self.quit_application)  # Connect quit signal to slot

    @pyqtSlot()
    def quit_application(self):
        """Slot to quit the application."""
        self.app.quit()
