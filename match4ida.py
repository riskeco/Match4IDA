
import json
import sys
from enum import IntEnum
from pathlib import Path

try:
    import pychrysalide
    from pychrysalide.analysis.contents import FileContent
    from pychrysalide.analysis.scan import ContentScanner
    from pychrysalide.analysis.scan import ScanOptions
    from pychrysalide.analysis.scan.patterns.backends import AcismBackend
except:
    pass

try:
    import yara
except:
    pass

try:
    import idaapi
    from PyQt5 import QtCore, QtWidgets
except:
    pass



class ScanHandler():
    """Generic handler for scan rules."""

    class ScannerType(IntEnum):
        YARA  = 0
        ROST  = 1
        GUESS = 2

    def __init__(self, rule_filename, rule_type, binary_filename):
        """Create a generic handler for scanning."""

        self._rule_filename = rule_filename
        self._rule_type = rule_type
        self._binary_filename = binary_filename


    def _guess_suitable_scanner(self):
        """Try to guess if a rule is for YARA or ROST."""

        with open(self._rule_filename, 'rb') as fd:
            content = fd.read()

        has_strings = b'strings:' in content
        has_bytes = b'bytes:' in content

        if has_strings and not(has_bytes):
            rtype = ScanHandler.ScannerType.YARA

        elif not(has_strings) and has_bytes:
            rtype = ScanHandler.ScannerType.ROST

        else:
            rtype = ScanHandler.ScannerType.GUESS

        return rtype


    def run(self):
        """Run a scan."""

        rtype = self._rule_type

        if rtype == ScanHandler.ScannerType.GUESS:
            rtype = self._guess_suitable_scanner()

        found = []

        if rtype == ScanHandler.ScannerType.YARA and 'yara' in sys.modules.keys():

            idaapi.msg('Running YARA against %s...' % self._binary_filename)

            rules = yara.compile(self._rule_filename)

            matches = rules.match(self._binary_filename)

            for m in matches:
                for s in m.strings:
                    for i in s.instances:

                        extra = {
                            'identifier': s.identifier,
                            'bytes': str(i),
                            'start': i.offset,
                            'length': i.matched_length
                        }

                        found.append(extra)

        elif rtype == ScanHandler.ScannerType.ROST and 'pychrysalide' in sys.modules.keys():

            idaapi.msg('Running ROST against %s...' % self._binary_filename)

            scanner = ContentScanner(filename=self._rule_filename)

            content = FileContent(self._binary_filename)

            options = ScanOptions()
            options.backend_for_data = AcismBackend

            ctx = scanner.analyze(options, content)

            data = scanner.convert_to_json(ctx)

            data = json.loads(data)

            for rule in data:
                for pat in rule['bytes_patterns']:
                    for m in pat['matches']:

                        extra = {
                            'identifier': pat['name'],
                            'bytes': m['content_str'].replace(r'\\', '\\'),
                            'start': m['offset'],
                            'length': m['length']
                        }

                        found.append(extra)

        return found



class MatchPanel(idaapi.PluginForm):
    """Panel for the IDA GUI."""

    def OnCreate(self, form):
        """Create a panel for the plugin activity."""

        parent = self.FormToPyQtWidget(form)

        # Create layout

        layout = QtWidgets.QGridLayout()

        parent.setLayout(layout)

        # Connection properties

        self._rule_filename = QtWidgets.QLineEdit()
        self._rule_filename.setText('/tmp/Match4IDA/Sample/APT_MAL_UNC4841_SEASPY_Jun23_1.yar')
        layout.addWidget(self._rule_filename, 0, 0)

        self._browse_button = QtWidgets.QPushButton('Browse')
        self._browse_button.clicked.connect(self._browse)
        layout.addWidget(self._browse_button, 0, 1)

        self._scanner_type = QtWidgets.QComboBox()
        self._scanner_type.addItems(['Yara', 'ROST', 'auto'])
        self._scanner_type.setCurrentIndex(2)
        layout.addWidget(self._scanner_type, 0, 2)

        self._scan_button = QtWidgets.QPushButton('Scan')
        self._scan_button.clicked.connect(self._run_scan)
        layout.addWidget(self._scan_button, 0, 3)

        # Match display

        self._rows = QtWidgets.QTableWidget()

        column_names = [ 'Identifier', 'Found bytes', 'Offset', 'Start location', 'Match size' ]

        self._rows.setColumnCount(len(column_names))
        self._rows.setHorizontalHeaderLabels(column_names)

        self._rows.setRowCount(0)
        self._rows.doubleClicked.connect(self._jump_to_match_location)

        header = self._rows.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)

        # fromRow - fromColumn - rowSpan - columnSpan
        layout.addWidget(self._rows, 1, 0, 1, 4)


    def _browse(self):
        """Select a rule as analysis source."""

        dlg = QtWidgets.QFileDialog()
        dlg.setFileMode(QtWidgets.QFileDialog.ExistingFile)
        dlg.setNameFilter('YARA rules (*.yar);;ROST rules (*.rost)')

        if dlg.exec_():

            filename = str(Path(dlg.selectedFiles()[0]))

            self._rule_filename.setText(filename)


    def _run_scan(self):
        """Run a scan and display the results."""

        rule_filename = self._rule_filename.text()
        rule_type = self._scanner_type.currentIndex()
        binary_filename = idaapi.get_input_file_path()

        if len(rule_filename) == 0:
            return

        scanner = ScanHandler(rule_filename, rule_type, binary_filename)

        matches = scanner.run()

        self._rows.setRowCount(0)

        for m in matches:

            index = self._rows.rowCount()
            self._rows.setRowCount(index + 1)

            item = QtWidgets.QTableWidgetItem(m['identifier'])
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)

            self._rows.setItem(index, 0, item)

            item = QtWidgets.QTableWidgetItem(m['bytes'])
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)

            self._rows.setItem(index, 1, item)

            item = QtWidgets.QTableWidgetItem('0x%x' % m['start'])
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)

            self._rows.setItem(index, 2, item)

            ea = idaapi.get_fileregion_ea(m['start'])

            item = QtWidgets.QTableWidgetItem('0x%x' % ea)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)

            self._rows.setItem(index, 3, item)

            item = QtWidgets.QTableWidgetItem('0x%x' % m['length'])
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)

            self._rows.setItem(index, 4, item)

            self._rows.update()

        idaapi.msg('Found %u match(es)\n' % self._rows.rowCount())


    def _jump_to_match_location(self, item):

        addr = int(self._rows.item(item.row(), 3).text(), 16)

        idaapi.jumpto(addr)



class Match4IDA(idaapi.plugin_t):

    flags = idaapi.PLUGIN_KEEP
    comment = 'Navigate to rule matched locations inside IDA.'

    wanted_name = 'Match4IDA'
    wanted_hotkey = ''
    help = 'Scan the current open binary against byte patterns.'


    def init(self):
        """Init the IDA plugin."""

        idaapi.msg('Starting %s\n' % self.wanted_name)

        self._form = None

        return idaapi.PLUGIN_KEEP


    def run(self, arg):
        """Run the IDA plugin."""

        idaapi.msg('Running %s\n' % self.wanted_name)

        self._form = MatchPanel()
        self._form.Show('Scan matches')


    def term(self):
        """Terminate the IDA plugin."""

        idaapi.msg('Terminating %s\n' % self.wanted_name)



def PLUGIN_ENTRY():
    return Match4IDA()



if __name__ == '__main__':
    """Script entrypoint."""

    has_yara = 'yara' in sys.modules.keys()

    if not(has_yara or False):
        print('At least one scanner is requiered')

    inside_ida = 'ida_idaapi' in sys.modules.keys()

    if not(inside_ida):

        if len(sys.argv) != 3:
            print('Usage: %s <rule> <binary>' % sys.argv[0])
            sys.exit(2)

        rule_filename = sys.argv[1]
        binary_filename = sys.argv[2]

        scanner = ScanHandler(rule_filename, ScanHandler.ScannerType.GUESS, binary_filename)

        matches = scanner.run()

        for m in matches:
            print('0x%x:%s:' % (m['start'], m['identifier']), m['bytes'])
