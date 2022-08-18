# PowerShellScriptBlockExtractor
A python 3 script to re-create Powershell script block from windows event logs(evtx).

Ported https://github.com/matthewdunwoody/block-parser from python 2 to python 3. Also rework some part of the script due to errors encountered when generating etree from the event log.

## usage
You need Admin rights if you are accessing `C:\WINDOWS\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`.

```shell
python script_block_extract.py -h

optional arguments:
  -h, --help            show this help message and exit
  -e EVTX, --evtx EVTX  Path to the Microsoft-Windows-
                        PowerShell%4Operational.evtx event log file to parse.
                        Default to C:\WINDOWS\System32\winevt\Logs\Microsoft-
                        Windows-PowerShell%4Operational.evtx
  -i SCRIPT_ID, --script_id SCRIPT_ID
                        Script block ID to parse
  -o OUTPUT, --output OUTPUT
                        Output directory for script blocks.
  -s, --slient          Print to screen

# Default will print to console. Disable it using `-s` or `--slient`.
script_block_extract.py -s

# Output all to a folder using `-o`
script_block_extract.py -o C:\users\user\desktop\scriptblocks

# output only selected script block id using `-i`
script_block_extract.py -i 2475f800-eaad-4ebe-9bba-659fe26b9958
```


## Dependencies
- python-evtx
- lxml
## Reference
- https://github.com/matthewdunwoody/block-parser
