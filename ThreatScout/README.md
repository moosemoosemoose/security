![Alt text for screen readers](../threaticon.png)
## ThreatScout
----------------------------------------------
## Installation

Clone this repository and install dependencies:

```bash
git clone https://github.com/yourusername/ThreatScout.git
cd ThreatScout
pip install --upgrade pip
pip install -r requirements.txt
```

Dependencies include:

pefile – For PE analysis

yara-python – YARA rule scanning

tqdm – Progress bars

pywin32 – Windows publisher detection (GetFileVersionInfo)

python-magic-bin – File type detection on Windows

⚠️ Windows Store Python users: For yara-python to work reliably, use a Python.org installer rather than the Windows Store version.

This ensures ThreatScout is ready to run from the command line with:
```bash
python main.py -p "C:\path\to\scan"
```
Scan results will be automatically saved to a timestamped log in the logs/ directory.




