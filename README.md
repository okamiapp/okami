# ōkami
### Advanced Binary Fingerprinting for Malware Attribution and Code Re-use Detection 
![alt text](https://github.com/okamiapp/okami/blob/main/img/okami-logo.png)

## Overview

Okami is an advanced toolset developed to enhance malware research and cybersecurity analysis. The core functionality of Okami lies in its ability to export and individually hash all subroutines within a binary. These hashes serve as a unique fingerprint, enabling a comprehensive comparison against a database of known binaries.  It empowers researchers to meticulously use disassembled code to build a database of malicious files and then use the tool to compare new samples against that database for attribution. Okami works with renowned frameworks like Capstone and Ghidra. The tool will be released at BlackHat 2024, USA and will be fully open-sourced with the entire codebase available on GitHub.

### Key Points 

This tool is devloped in Python. The tool can be used with Capstone. 
As part of the Project Okami, there are other tools included (by the same author) that can be used for dynamic, advanced analysis such as Lupo (released at BlackHat in 2022). 

Licensing: LGPL-2.1 license (GNU LESSER GENERAL PUBLIC LICENSE)

### Features

- **Multiple File Selection**: Users can select and process multiple files in one go, enhancing productivity.
- **Capstone Integration**: Leverages the Capstone disassembly engine for accurate and detailed disassembly outputs.
- **Multiple File Selection**: Users can select and process multiple files in one go, enhancing productivity.
- **Capstone Integration**: Leverages the Capstone disassembly engine for accurate and detailed disassembly outputs.
- **Comprehensive Logging**: Logs all actions, errors, and critical information for easy troubleshooting and review.
- **SHA-256 Hashing**: Generates SHA-256 hashes for all processed binaries and their functions for integrity checks and comparisons.
- **Database Storage**: Stores hashes and disassembly information in a SQLite database, allowing for efficient querying and analysis.
- **Duplicate Detection**: Automatically detects and skips duplicate files based on SHA-256 hashes.
- **Heuristic-Based Detection**: Uses heuristic methods to identify functions within binaries when export symbols are not available.
- **User-friendly GUI**: Simplifies the disassembly process with an intuitive graphical interface, making it accessible to users of all skill levels.
- **Cross-Platform Compatibility**: Works on Linux, Windows, and macOS, ensuring wide usability.

## Installation

### Prerequisites

- **Python 3.6** or higher
- **Tkinter** for Python (usually comes with Python installation)
- **Capstone** disassembly framework
- **Humanize** library for human-readable file sizes
- **SQLite3** for database management
- **pefile** for parsing PE files
- **lief** for parsing ELF files
- **filetype** for identifying file types
- **tqdm** for progress bars
- **pandas** for data manipulation
- **requests** for HTTP requests
- **readline** for command-line interaction

### Downloading the Tool
Clone the repository or download the source code:

```bash
git clone https://github.com/okamiapp/okami 
cd okami-main 
```

### Installing Packages 

To install all necessary packages, run the following command in your terminal: 

```bash
pip3 install -r requirements.txt
```

## Usage

### Running the Disassembler
To run the Okami disassembler, execute the main script:

```bash
python3 okami.py
```

### Analyzing Samples 
- **Launch the Tool**: Start the Okami disassembler by running the main script as shown above.
- **Upload Files**: Follow the on-screen instructions to upload the binary files you wish to analyze. You can select and process multiple files simultaneously.
- **View Progress**: The tool provides a progress bar to show the status of the analysis. Logs will also be generated for detailed tracking of actions and errors.
- **Review Results**: Once the analysis is complete, the results, and disassembly outputs, are stored in a SQLite database. You can review these results within the tool or export them as needed.

### Additional Features
- **Logging**: All actions and errors are logged in a file named okami.log for easy troubleshooting and review.
- **Database Management**: The tool uses a SQLite database (Okami.db) to store and manage the hashes and disassembly information. This database can be queried for efficient analysis and comparison of new samples.
- **Heuristic-Based Detection**: When export symbols are not available, Okami uses heuristic methods to identify functions within binaries, ensuring comprehensive analysis.

### Sample Workflow
- **Prepare Environment**: Ensure all prerequisites are installed and the requirements.txt file has been used to set up the environment.
- **Download and Setup Okami**: Clone the repository and navigate to the main directory.
- **Run Analysis**: Execute python3 okami.py and follow the prompts to upload and analyze binary files.
- **Check Logs**: Refer to the okami.log file for detailed logs of the analysis process.
- **Manage Database**: Use SQLite commands or a database management tool to query and manage the results stored in Okami.db.

## Troubleshooting
### Common Issues
- Installation Errors: Ensure all prerequisites are installed and the requirements.txt file is used to install all necessary packages.
- File Upload Problems: Make sure the files you are uploading are supported binary formats (PE or ELF).
- Database Connection Issues: Verify that the SQLite database file (Okami.db) exists in the correct directory.

## Solutions
- Reinstall Packages: Run pip3 install -r requirements.txt again to ensure all dependencies are correctly installed.
- Check Logs: Refer to the okami.log file for detailed error messages and troubleshooting information.

## FAQ
### What types of files can Okami analyze?
Okami can analyze PE (Portable Executable) and ELF (Executable and Linkable Format) binary files.

### How does Okami handle duplicate files?
Okami generates SHA-256 hashes for all processed binaries and uses these hashes to detect and skip duplicate files.

### How can I contribute to Okami?
Contributions are welcome! Please fork the repository and submit a pull request with your changes. For major changes, open an issue first to discuss what you would like to change.

## Community and Support
Join our discussion forum or Slack channel (coming soon!) for community support and discussions. 

## Change Log
### Version 1.0.0
Initial release with basic functionality including multiple file selection, Capstone integration, and SQLite database management. 

## Contributing
Contributions are welcome! If you'd like to contribute, please fork the repository and submit a pull request with your changes. For major changes, please open an issue first to discuss what you would like to change.

## License 
See the [License](https://github.com/malienist/okami/blob/main/LICENSE) file for details. 

# 3rd August 3:56pm: 
## 76 Samples in DB 

- AgentTesla
- Artemis
- AsyncRAT
- Azorult
- Blackmatter
- Clop
- CryptoLocker_10Sep2013
- CryptoLocker_20Nov2013
- CryptoLocker_22Jan2014
- DCRat
- Darkside
- Dharma-Crysis
- Dridex
- Emotet
- Formbook
- Icedid
- LockBit
- Maze
- Mimikatz
- Mirai
- Netwalker
- Nivdort
- NjRAT
- Petya-NotPetya
- RansomEXX
- Ransomware.Cerber
- Ransomware.Mamba
- Ransomware.Petrwrap
- Ransomware.Unnamed_0
- Ransomware.WannaCry
- Ransomware.WannaCry_Plus
- RedLineStealer
- Remcos
- Rombertik
- Rustock-23
- Rustock.C
- Rustock.E
- Rustock.I
- Rustock.J
- Rustock.NFE
- Ryuk
- SmokeLoader
- Sodinokibi
- Somoto
- TrickBot
- Trojan.Bladabindi
- Trojan.Destover-SonySigned
- Trojan.Dropper.Gen
- Trojan.Kovter
- Trojan.Loadmoney
- Trojan.NSIS.Win32
- TrojanWin32.Duqu.Stuxnet
- Vidar
- W32.Elkern.B
- W32.Klez.E
- W32.Klez.H
- W32.Nimda.A
- W32.Nimda.E
- W32.Slammer
- W32.Swen
- WannaCry
- Win32.AgentTesla
- Win32.GravityRAT
- Win32.Infostealer.Dexter
- Win32.LuckyCat
- Win32.SofacyCarberp
- Win32.Unclassified
- Win32.WannaPeace
- XORDDoS
- Zeus
- ZeusBankingVersion_26Nov2013
- agent_tesla
- amadey
- kelihos
- njRAT-v0.6.4
- olderAsprox 
 
---
