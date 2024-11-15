# YPScanLite

YARA and IOC scanner that is built on rust and uses the new YARA-X engine. Scanner was inspired from [Loki](https://github.com/Neo23x0/Loki) scanner that is built on Python retaining the following features:

* Load and scan using Yara rules.
* Load and scan using hashes in MD5, SHA1, and SHA256.
* Exclude paths using regex
* Exclude hashes

as well as the following additional features:

* Progress tracking
* Encrypt Yara rule files and hashes to avoid false positive AV detection when mass deploying the scanner.
* Detect and display digital signature information for PE files in Windows.
* Multi-threaded scan for a faster scan.
* Ability to scan with no file size limit (check [no size limit](#Scanning-with-no-file-size-limit) section for more information).
* Both csv and json support in both console and file output.
* Ability to encode in ANSI for Windows to solve some encoding issues when piping output to collection agents or programs in non-English versions of Windows.

## Usage

Scan subcommand:

    starts a file scan, by default scan all drives with 150 MB size limit and uses 1/2 CPUs

    Usage: YPScan scan [OPTIONS]

    Options:
      -a, --all-drives        Scan all drives including removable (in windows only)
      -r, --all-reasons       Display all match reasons instead of only 9
      -p, --path <PATH>       Path to be scanned instead of all fixed drives
      -n, --no-size           Removes file size limit. Increased RAM usage possible depending on yara rules.
      -s, --size <NUMBER>     Max size filter (in KB) to ignore large files in scan
      -t, --threads <NUMBER>  Number of threads to use in scan
          --power             Power scan mode, uses all avaliable cpu
          --no-progress       Disable progress display and tracking
          --only-alerts       Filter output level to alerts and higher
          --no-color          Switch off console color
          --no-output         Switch off console output
          --csv-output        Change console logging to csv
          --json-output       Change console logging to json
          --no-log            Switch off file output
          --csv-log           Change log file format to csv
          --json-log          Change log file format to json
          --ansi-encoding     Enable encoding using windows ansi pages, only works in non tty
      -d, --debug             Enable more informative logging for debugging
      -v, --trace             Enable extream logging for debugging
      -h, --help              Print help
      -V, --version           Print version

Encrypt/Decrypt subcommand:

    encrypts yara file in order to avoid false positive AV detections

    Usage: YPScan encrypt [OPTIONS] [FILE]

    Arguments:
      [FILE]  Path to file to be encrypted

    Options:
      -o, --output-path <PATH>  Path to output encrypted files
          --only-alerts         Filter output level to alerts and higher
          --no-color            Switch off console color
          --no-output           Switch off console output
          --csv-output          Change console logging to csv
          --json-output         Change console logging to json
          --no-log              Switch off file output
          --csv-log             Change log file format to csv
          --json-log            Change log file format to json
          --ansi-encoding       Enable encoding using windows ansi pages, only works in non tty
      -d, --debug               Enable more informative logging for debugging
      -v, --trace               Enable extream logging for debugging
      -h, --help                Print help
      -V, --version             Print version

## Signature files

In order to maintain a few centralized sources of open source rules and iocs, signatures can be found in [signature-base](https://github.com/Neo23x0/signature-base) and [reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules). However, you have to copy files to their correct folders in the tool own structure (.txt files must be converted to .ioc for hashes). An updater tool is planned to grap the lastest rules and iocs and make this process easier.

Note: Release downloads already have YARA and IOCS packaged and updated at the time of release.

## Scanning with no file size limit

This scanner allows users to disabled file size limit with -n or --no-size which might result in higher RAM usage. However, the tool went thorough testing when it comes to scanning with large file sizes and optimizations went to that process as much as possible.
Due to how the scanner is built many components are in play here:

* File hasher is optimized well and doesn't use any RAM when hashing large files due to read buffering.
* Yara scanner uses YARA-X engine and depending on the type of rules used, RAM usage will vary.
* All other components are optimized and tested and doesn't use that much RAM no matter the file size.

To summarize, the type of Yara rules loaded will determine how much RAM the scanner is going to use when it comes to scanning single large files.

## TO BE DONE

- [ ] Add filename ioc.
- [ ] Add an updater process in order to get up-to-date yara and iocs.
- [ ] Add c2 ioc.
- [ ] Add ability to scan processes (Waiting for YARA-X to support that feature).

## Credit

+ Special thanks to [Neo23x0 (Florian Roth)](https://github.com/Neo23x0) for his inspiration, which led to creating this project.
+ Special thanks to the [VirusTotal team](https://github.com/VirusTotal) for their YARA-X engine.
+ Special thanks to crate owners whose crates are used in this project, which can be found in the cargo.toml file.