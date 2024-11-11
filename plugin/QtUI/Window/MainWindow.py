from typing import Dict, Any

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QStackedWidget, QHBoxLayout, QLabel

from qfluentwidgets import (NavigationInterface, NavigationItemPosition,  MessageBox,
                            isDarkTheme, qrouter, InfoBar, InfoBarPosition)
from qfluentwidgets import FluentIcon as FIF
from qframelesswindow import FramelessWindow, TitleBar

from DbgInfo import DbgConst
from QtUI import UI
from QtUI.Widget.AssemblyWidget import AssemblyWidget
from QtUI.Widget.AvatarWidget import AvatarWidget
from QtUI.Widget.DefaultWidget import DefaultWidget
from QtUI.Widget.LoggerWidget import LoggerWidget
from QtUI.Widget.SettingWidget import SettingWidget


class CustomTitleBar(TitleBar):
    """ Title bar with icon and title """
    def __init__(self, parent):
        super().__init__(parent)
        # add window icon
        self.iconLabel = QLabel(self)
        self.iconLabel.setFixedSize(18, 18)
        self.hBoxLayout.insertSpacing(0, 10)
        self.hBoxLayout.insertWidget(1, self.iconLabel, 0, Qt.AlignLeft | Qt.AlignBottom)
        self.window().windowIconChanged.connect(self.setIcon)
        # add title label
        self.titleLabel = QLabel(self)
        self.hBoxLayout.insertWidget(2, self.titleLabel, 0, Qt.AlignLeft | Qt.AlignBottom)
        self.titleLabel.setObjectName('titleLabel')
        self.window().windowTitleChanged.connect(self.setTitle)
    def setTitle(self, title):
        self.titleLabel.setText(title)
        self.titleLabel.adjustSize()
    def setIcon(self, icon):
        self.iconLabel.setPixmap(QIcon(icon).pixmap(18, 18))


class Window(FramelessWindow):

    def __init__(self,ui:UI):
        super().__init__()
        self.ui = ui
        self.setTitleBar(CustomTitleBar(self))
        self.hBoxLayout = QHBoxLayout(self)
        self.navigationInterface = NavigationInterface(self, showMenuButton=True, showReturnButton=True)
        self.stackWidget = QStackedWidget(self)
        # create sub interface
        self.defaultInterface = DefaultWidget('Default Interface', self)
        self.assemblyInterface = AssemblyWidget(self.ui, self)
        self.loggerInterface = LoggerWidget('logger Interface', self)

        self.settingInterface = SettingWidget('Setting Interface', self)
        self.initLayout()
        self.initNavigation()
        self.initWindow()

    def setQss(self):
        color = 'dark' if isDarkTheme() else 'light'
        with open(f'plugin/QtUI/resource/qss/{color}/demo.qss', encoding='utf-8') as f:
            style = f.read()
            self.setStyleSheet(style)

    def initLayout(self):
        self.hBoxLayout.setSpacing(0)
        self.hBoxLayout.setContentsMargins(0, 0, 0, 0)
        self.hBoxLayout.addWidget(self.navigationInterface)
        self.hBoxLayout.addWidget(self.stackWidget)
        self.hBoxLayout.setStretchFactor(self.stackWidget, 1)
        self.titleBar.raise_()
        self.navigationInterface.displayModeChanged.connect(self.titleBar.raise_)

    def initWindow(self):
        self.setWindowIcon(QIcon('plugin/QtUI/resource/Wker.jpg'))
        self.setWindowTitle("DebuggerLogger")
        self.titleBar.setAttribute(Qt.WA_StyledBackground)
        # 设置窗口大小
        self.resize(1200, 900)
        desktop = QApplication.desktop().availableGeometry()
        w, h = desktop.width(), desktop.height()
        self.move(w//2 - self.width()//2, h//2 - self.height()//2)
        self.setQss()

    def showAvatarInfo(self):
        w = MessageBox(
            '支持作者🥰',
            '个人开发不易，如果这个项目帮助到了您，可以考虑请作者喝一瓶快乐水🥤。您的支持就是作者开发和维护项目的动力🚀',
            self
        )
        w.yesButton.setText('来啦老弟')
        w.cancelButton.setText('下次一定')
        w.exec()

    def initNavigation(self):
        # enable acrylic effect
        self.addSubInterface(self.defaultInterface, FIF.HOME, 'Default')
        self.addSubInterface(self.assemblyInterface, FIF.IOT, 'Assembly')
        self.navigationInterface.addSeparator()
        # add navigation items to scroll area
        self.addSubInterface(self.loggerInterface, FIF.HISTORY, 'Logger', NavigationItemPosition.SCROLL)
        # add custom widget to bottom
        self.navigationInterface.addWidget(
            routeKey='avatar',
            widget=AvatarWidget(),
            onClick=self.showAvatarInfo,
            position=NavigationItemPosition.BOTTOM
        )
        self.addSubInterface(self.settingInterface, FIF.SETTING, 'Settings', NavigationItemPosition.BOTTOM)
        #!IMPORTANT: don't forget to set the default route key
        qrouter.setDefaultRouteKey(self.stackWidget, self.defaultInterface.objectName())
        # set the maximum width
        # self.navigationInterface.setExpandWidth(300)
        self.stackWidget.currentChanged.connect(self.onCurrentInterfaceChanged)
        self.stackWidget.setCurrentIndex(1)

    def onCurrentInterfaceChanged(self, index):
        widget = self.stackWidget.widget(index)
        self.navigationInterface.setCurrentItem(widget.objectName())
        qrouter.push(self.stackWidget, widget.objectName())

    def switchTo(self, widget):
        self.stackWidget.setCurrentWidget(widget)

    def addSubInterface(self, interface, icon, text: str, position=NavigationItemPosition.TOP):
        """ add sub interface """
        self.stackWidget.addWidget(interface)
        self.navigationInterface.addItem(
            routeKey=interface.objectName(),
            icon=icon,
            text=text,
            onClick=lambda: self.switchTo(interface),
            position=position,
            tooltip=text
        )

    def resizeEvent(self, e):
        self.titleBar.move(46, 0)
        self.titleBar.resize(self.width()-46, self.titleBar.height())

    def closeEvent(self, event):
        InfoBar.error(
            title=self.tr('错误'),
            content=self.tr("不允许退出，等待程序退出"),
            orient=Qt.Horizontal,
            isClosable=True,
            position=InfoBarPosition.TOP_RIGHT,
            duration=2000,
            parent=self
        )
        event.ignore()



    def enter_dbg(self, dbg: int, pi: Dict[str, Any], process_name: str, dbg_name: str) -> int:
        return self.assemblyInterface.enter_dbg(dbg, pi, process_name, dbg_name)

    def exit_dbg(self, dbg: int):
        return self.assemblyInterface.exit_dbg(dbg)

    def unknow_exception_callback(self, dbg: int,ctx: Dict,exception: Dict) -> int:
        return self.assemblyInterface.unknow_exception_callback(dbg,ctx,exception)

    def bp_callback(self, dbg: int, bp: Dict[str, Any], ctx: Dict[str, Any]) -> int:
        return self.assemblyInterface.bp_callback(dbg, bp, ctx)

    def create_process_callback(self, dbg: int, create_process_debug_info: Dict[str, Any]) -> int:
        return self.assemblyInterface.create_process_callback(dbg, create_process_debug_info)

    def load_dll_callback(self, dbg: int, load_dll_debug_info: Dict[str, Any]) -> int:
        return self.assemblyInterface.load_dll_callback(dbg, load_dll_debug_info)

    def unload_dll_callback(self, dbg: int, unload_dll_debug_info: Dict[str, Any]) -> int:
        return self.assemblyInterface.unload_dll_callback(dbg, unload_dll_debug_info)

    def create_thread_callback(self, dbg: int, create_thread_debug_info: Dict[str, Any]) -> int:
        return self.assemblyInterface.create_thread_callback(dbg, create_thread_debug_info)

    def exit_thread_callback(self, dbg: int, exit_thread_debug_info: Dict[str, Any]) -> int:
        return self.assemblyInterface.exit_thread_callback(dbg, exit_thread_debug_info)

    def output_string_callback(self, dbg: int, debug_string: Dict[str, Any]) -> int:
        return self.assemblyInterface.output_string_callback(dbg, debug_string)

    def exit_process_callback(self, dbg: int, exit_process_debug_info: Dict[str, Any]) -> int:
        return self.assemblyInterface.exit_process_callback(dbg, exit_process_debug_info)

