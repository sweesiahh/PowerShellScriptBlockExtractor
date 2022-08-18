import os
import argparse

from collections import defaultdict

from lxml import etree
from lxml.etree import XMLSyntaxError

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view

POWERSHELL_EVTX_PATH = r'%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx'
POWERSHELL_EVTX_PATH = os.path.expandvars(POWERSHELL_EVTX_PATH)

def to_lxml(record_xml):
    """
    @type record: Record
    """
    try:
        return etree.fromstring(f'<?xml version=\"1.0\" ?> {record_xml}')
    except Exception as e:
        print(e)
        return None


class ScriptBlockEntry(object):
    def __init__(self, level, computer, timestamp, message_number, message_total, script_block_id, script_block_text):
        super(ScriptBlockEntry, self).__init__()
        self.level = level
        self.computer = computer
        self.timestamp = timestamp
        self.message_number = message_number
        self.message_total = message_total
        self.script_block_id = script_block_id
        self.script_block_text = script_block_text

    def get_metadata(self):
        return self.script_block_id + "," + str(self.timestamp) + "," + str(self.level) + "," + str(
            self.message_total) + "," + self.computer + "," + str(self.message_number)


class Entry(object):
    def __init__(self, xml, record):
        super(Entry, self).__init__()
        self._xml = xml
        self._record = record
        self._node = to_lxml(self._xml)
        self.ns = {"default": self._node.nsmap[None]}
        self.default_ns = "default:"

    def get_xpath(self, path):
        # add default namespace
        paths = path.split('/')
        new_path = f'/'
        for item in paths:
            if item:
                new_path += f'/{self.default_ns}{item}'
        temp = self._node.xpath(new_path, namespaces=self.ns)
        return temp[0]

    def get_eid(self):
        eid_str = self.get_xpath(f"/System/EventID")
        return int(eid_str.text)

    def get_script_block_entry(self):
        level = int(self.get_xpath(f"/System/Level").text)
        computer = self.get_xpath(f"/System/Computer").text
        timestamp = self._record.timestamp()
        message_number = int(self.get_xpath(f"/EventData/Data[@Name='MessageNumber']").text)
        message_total = int(self.get_xpath(f"/EventData/Data[@Name='MessageTotal']").text)
        script_block_id = self.get_xpath(f"/EventData/Data[@Name='ScriptBlockId']").text
        script_block_text = self.get_xpath(f"/EventData/Data[@Name='ScriptBlockText']").text
        return ScriptBlockEntry(level, computer, timestamp, message_number, message_total, script_block_id,
                                script_block_text)


def get_entries(evtx):
    """
    @rtype: generator of Entry
    """
    try:
        for xml, record in evtx_file_xml_view(evtx.get_file_header()):
            try:
                yield Entry(xml, record)
            except Exception as e:  # etree.XMLSyntaxError as e:
                print(e)
                continue
    except Exception as e:
        print(e)
        yield None


def xml_records(filename: str):
    """
    If the second return value is not None, then it is an
      Exception encountered during parsing.  The first return value
      will be the XML string.
    @type filename str
    @rtype: generator of (etree.Element or str), (None or Exception)
    """
    with Evtx(filename) as evtx:
        for xml, record in evtx_file_xml_view(evtx.get_file_header()):
            try:
                yield Entry(xml, record)
            except etree.XMLSyntaxError as e:
                print(e)
                yield None


def get_entries_with_eids(filename: str, eids):
    for entry in xml_records(filename):
        try:
            if entry is not None and entry.get_eid() in eids:
                yield entry
        except Exception as e:
            print(e)
            continue


def process_entries(entries, script_id=None):
    # s = script id
    # a = all
    # o = output
    # f = file
    # m = metadata
    blocks = defaultdict(list)

    for entry in entries:
        sbe = entry.get_script_block_entry()
        if not script_id:
            blocks[sbe.script_block_id].insert(sbe.message_number, sbe.script_block_text)
        else:
            if sbe.script_block_id == script_id:
                blocks[sbe.script_block_id].insert(sbe.message_number, sbe.script_block_text)

        # blocks[sbe.script_block_id].insert(sbe.message_number,
        # sbe.script_block_text.replace("&lt;", ">").replace("&gt;", "<"))
    return blocks


def output_result(blocks, folder=None, silent=False):
    # re-create the script
    # output to console if silent is false
    # if folder is specified, will write to file
    # return full file path
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)

    files_written = 0
    for script_id in blocks:
        text = ''
        for block in blocks[script_id]:
            text += block
        if not silent:
            print(text)
        if folder:
            with open(os.path.join(folder, f"{script_id}.txt"), 'w') as file_h:
                file_h.write(text)
                files_written += 1
    if folder:
        print(f"{files_written} written to {folder}")


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Parse PowerShell script block log entries (EID 4104) out of the Microsoft-Windows-PowerShell%4Operational.evtx event log.")
    parser.add_argument("-e", "--evtx", type=str, default=POWERSHELL_EVTX_PATH,
                        help=f'Path to the Microsoft-Windows-PowerShell%4Operational.evtx event log file to parse. '
                             f'Default to {POWERSHELL_EVTX_PATH}'.replace('%', '%%'))
    parser.add_argument("-i", "--script_id", type=str, default=None,
                        help="Script block ID to parse")
    parser.add_argument("-o", "--output", type=str,
                        help="Output directory for script blocks.")
    parser.add_argument("-s", "--slient", action='store_true',
                        help="Print to screen")
    args = parser.parse_args()

    entries_ = get_entries_with_eids(args.evtx, set([4104]))
    block_ = process_entries(entries_, args.script_id)
    output_result(block_, args.output, args.slient)


if __name__ == "__main__":
    main()
