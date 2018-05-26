# evt2sigma
Log Entry to Sigma Rule Converter

# What it does

It takes a log entry from a file and tries to create a [Sigma](https://github.com/Neo23x0/sigma) rule. It is optimized for the XML format of Windows EVTX event logs but can be easily modified to support more log formats by adding a new regular expression for the respective log type. 

# Status

The current state is "alpha". It's more like a public POC so that others can learn and extend. 

# Usage

    usage: evt2sigma.py [-h] [-f file] [-o out-file] [-fc field-count] [--debug]
                        [--trace] [-a] [-r] [-l] [-t] [-d] [-p] [-s] [-c]

    Event 2 Sigma Converter

    optional arguments:
      -h, --help       show this help message and exit
      -f file          Read the log entry from a file
      -o out-file      Write rule to an output file
      -fc field-count  use the top X fields
      --debug          Debug output
      --trace          Trace output

    Fields:
      -a               Author name
      -r               Reference
      -l               Level
      -t               Title
      -d               Description
      -p               Product (e.g. windows, linux)
      -s               Service (e.g. security, sysmon)
      -c               Category (e.g. proxy)
      
# Screenshot

![evt2sigma Screenshot](https://github.com/Neo23x0/evt2sigma/blob/master/screenshots/screen-0.0.1.png "Example of conversion")
