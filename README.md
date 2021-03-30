# BitsParser

A python tool to parse Windows Background Intelligent Transfer Service database files.


## Intro

BitsParser is a Python 3 script that can parse Windows Background Intelligent Transfer Service database files and extract job and file information.  It supports both the original custom database format as well as the ESE database format used on Windows 10 systems.


## Installation

BitsParser is written in Python 3.

Before running the tool, you will have to install required packages defined in requirements.txt.  To do this, run the following command (may require administrator-level privileges):

`pip install -r requirements.txt`

## Usage

To use BitsPaser, simply run BitsParser.py with Python 3.  There are some options that can be specified to control carving, inputs, and outputs.

```
usage: BitsParser.py [-h] [--input INPUT] [--output OUTPUT] [--carvedb]
                     [--carveall]

optional arguments:
  -h, --help       show this help message and exit
  --input INPUT    Optionally specify the directory containing QMGR databases
                   or the path to a file to process.
  --output OUTPUT  Optionally specify a file for JSON output. If not specified
                   the output will be printed to stdout.
  --carvedb        Carve deleted records from database files
  --carveall       Carve deleted records from all other files
```

By default BitsParser will process files in the `%ALLUSERSPROFILE%\Microsoft\Network\Downloader`.  Use the `-i` option to specify an alternate file or directory.  The script can be used with offline files from alternate operating systems.

By default BitsParser will output the parsing results in JSON format to stdout.  To direct the output to a file, use the `-o` option.

By default BitsParser will only parse and output active jobs and files.  To carve deleted entries from the database use `--carvedb`.  To carve entries from all file types, including transaction logs, use `--carveall`.

## Acknowledgments

This product includes software developed by SecureAuth Corporation (https://www.secureauth.com/).
