#!/usr/bin/env python3

__AUTHOR__ = 'Florian Roth'
__VERSION__ = "0.0.1 May 2018"

"""
Install dependencies with:

pip3 install colorama
"""

import re
import operator
import datetime
from itertools import islice
import argparse
from colorama import init, Fore, Back, Style
import sys

# Config

XML = r'<([\w]+)[^\>\/]*>([^<]+)<\/'
XML_DATA = r'<[\w]+ Name="([^\"]+)">([^<]+)<\/'
CP1 = r' ([A-Za-z_]+): ([^;]+)[;]?'
DEF1 = r' (from|to|protocol|proto|src|dst|service|id|port|dstport|srcport)[:]? ["\']?([\w.:]+)["\']?'
DEF2 = r' (from|to|protocol|proto|src|dst|service|id|port|dstport|srcport)=["\']?([\w.:]+)["\']?'

REGEX_SET = [XML_DATA, XML, CP1, DEF1, DEF2]

SIGMA_TEMPLATE = """
title: %%%title%%%
status: experimental
description: '%%%description%%%'
date: %%%date%%%
references:
    - %%%reference%%%
author: %%%author%%%
logsource:
    %%%logsource%%%
detection:
    selection: %%%selection%%%
    condition: selection
falsepositives:
    - Unknown
level: %%%level%%%
"""

UNUSABLE_FIELDS = ['rule_uid', 'ruleid']

# Program

def read_file(file_path):
    """
    Reads a file and returns the string
    :param file_path:
    :return:
    """
    with open(file_path, 'r') as fh:
        return fh.read()

def generate_sigma(kvs, args):
    """
    Generates a Sigma rule using a set of key/value pairs
    :param kvs: key/value pairs as dictionary
    :return rule: rule string
    """
    # Replace values in template
    rule = SIGMA_TEMPLATE
    rule = rule.replace('%%%title%%%', args.t)
    rule = rule.replace('%%%description%%%', args.d)
    rule = rule.replace('%%%reference%%%', args.r)
    rule = rule.replace('%%%author%%%', args.a)
    rule = rule.replace('%%%date%%%', datetime.datetime.today().strftime('%Y-%m-%d'))
    logsource = "product: %s" % args.p
    if args.s:
        logsource += "\n\tservice: %s" % args.s
    if args.c:
        logsource = "category: %s" % args.c
    rule = rule.replace('%%%logsource%%%', logsource)
    rule = rule.replace('%%%level%%%', args.l)

    # Create the selection
    selection = ""
    for k, v in kvs.items():
        # Integer
        if v.isdigit():
            selection_element = "\n\t%s: %s" % (k, v)
        else:
            selection_element = "\n\t%s: '%s'" % (k, v)
        selection += selection_element

    rule = rule.replace('%%%selection%%%', selection)

    return rule


def extract_values(string, re_set):
    """
    Extract the key/value pairs from the string
    :param string: event log entry string
    :param re_set: set of regular expressions to use
    :return:
    """
    kvs = {}
    for regex in re_set:
        extracted = dict(regex.findall(string, re.IGNORECASE))
        kvs = {**kvs, **extracted}
    return kvs


def take(n, iterable):
    """
    Return first n items of the iterable as a list
    :param n: number of items
    :param iterable: dictionary
    :return:
    """
    return list(islice(iterable, n))


def filter_kvs(kvs, top_count):
    """
    Filter key value pairs and set a score by key to improve the selection of relevant values
    :param kvs: key/value pairs
    :return keyscores: keys and their scores in a dictionary
    """
    key_scores = {}
    # Loop over key/value pairs
    for k, v in kvs.items():
        # Key not already set
        if k not in key_scores:
            key_scores[k] = 0

        # NEGATIVE SCORES
        # Empty values
        if v == "" or v == " " or v == "\n":
            key_scores[k] -= 50
        # Event Record Id
        if "recordid" in k.lower():
            key_scores[k] -= 20
        # Data Fields in Windows EVTX events
        if k == "Data":
            key_scores[k] -= 50
        # Computer Names
        if "computer" in k.lower():
            key_scores[k] -= 20
        # Timestamp
        if "time" in k.lower():
            key_scores[k] -= 30
        # GUIDs
        if "guid" in k.lower():
            key_scores[k] -= 20
        # Process IDs
        if "processid" in k.lower() or "processguid" in k.lower():
            key_scores[k] -= 20
        # Sysmon
        if k == "LogonGuid":
            key_scores[k] -= 30
        # Too many space values could indicate an error in extraction
        if v.count(" ") > 4:
            key_scores[k] -= 3
        # Too many space values could indicate an error in extraction
        if "version" in k.lower():
            key_scores[k] -= 2
        # Unusable fields
        for uf in UNUSABLE_FIELDS:
            if uf == k:
                key_scores[k] -= 30

        # POSITIVE SCORES
        # EventIDs
        if k == "EventID":
            key_scores[k] += 40

        # Generic Strings
        if k == "ImagePath":
            key_scores[k] += 20
        if k == "Type":
            key_scores[k] += 5
        if k == "Service":
            key_scores[k] += 5

        # Values
        if ".exe" in v.lower():
            key_scores[k] += 5
        if "temp" in v.lower():
            key_scores[k] += 5

        # Sysmon
        if k == "CommandLine":
            key_scores[k] += 40
        if k == "ParentImage":
            key_scores[k] += 20
        if k == "ParentCommandLine":
            key_scores[k] += 19
        if k == "NewProcessName":
            key_scores[k] += 15
        if k == "TokenElevationType":
            key_scores[k] += 5
        if k == "MD5" or k == "SHA1" or k == "SHA256" or k.lower() == "imphash":
            key_scores[k] += 15

    # Sort the key scores to get a list with decending scores
    key_scores = sorted(key_scores.items(), key=operator.itemgetter(1), reverse=True)
    if args.trace:
        print("Key scores:")
        print(key_scores)

    # Get only the top X kvs
    selected_kvs = {}
    count = 0
    for k, c in key_scores:
        selected_kvs[k] = kvs[k]
        count += 1
        if count > top_count:
            break

    return selected_kvs


if __name__ == '__main__':

    init(autoreset=False)

    print(Style.RESET_ALL)
    print(Fore.BLACK + Back.WHITE)
    print("     ____     __  ___  _____                 ".ljust(80))
    print("    / __/  __/ /_|_  |/ __(_)__ ___ _  ___ _ ".ljust(80))
    print("   / _/| |/ / __/ __/_\ \/ / _ `/  ' \/ _ `/ ".ljust(80))
    print("  /___/|___/\__/____/___/_/\_, /_/_/_/\_,_/  ".ljust(80))
    print("                          /___/              ".ljust(80))
    print(" ".ljust(80))
    print("  Converts a log line to a Sigma rule".ljust(80))
    print(("  " + __AUTHOR__ + " - " + __VERSION__ + "").ljust(80))
    print(" ".ljust(80) + Style.RESET_ALL)
    print(Style.RESET_ALL + " ")

    parser = argparse.ArgumentParser(description='Event 2 Sigma Converter')

    parser.add_argument('-f', help='Read the log entry from a file', metavar='file', default='')
    parser.add_argument('-o', help='Write rule to an output file', metavar='out-file', default='')

    parser.add_argument('-fc', help='use the top X fields', metavar='field-count', default='4')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
    parser.add_argument('--trace', action='store_true', default=False, help='Trace output')

    group_header = parser.add_argument_group('Fields')
    group_header.add_argument('-a', help='Author name', metavar='', default='Evt2Sigma')
    group_header.add_argument('-r', help='Reference', metavar='', default='Internal Research')
    group_header.add_argument('-l', help='Level', metavar='', default='medium')
    group_header.add_argument('-t', help='Title', metavar='', default='Relevant Event')
    group_header.add_argument('-d', help='Description', metavar='', default='Auto-generated Sigma rule')
    group_header.add_argument('-p', help='Product (e.g. windows, linux)', metavar='', default='windows')
    group_header.add_argument('-s', help='Service (e.g. security, sysmon)', metavar='', default='')
    group_header.add_argument('-c', help='Category (e.g. proxy)', metavar='', default='')

    args = parser.parse_args()
    if len(sys.argv) <2:
        parser.print_usage()
        sys.exit(1)

    # Prepare Regex set
    re_set = []
    for regex_string in REGEX_SET:
        regex = re.compile(regex_string)
        re_set.append(regex)

    # Read a log entry from a file
    entry = read_file(args.f)
    #if args.debug:
    print(Fore.BLACK + Back.WHITE, "Event Entry:", Style.RESET_ALL)
    print("")
    print(entry)
    print("")

    # Parse the log entry
    kvs = extract_values(entry, re_set)
    if args.trace:
        print("All extracted key value pairs:")
        print(kvs)
    selected_kvs = take(int(args.fc), kvs.items())

    # Generate a rule
    rule = generate_sigma(filter_kvs(kvs, int(args.fc)), args)
    #if args.debug:
    print(Fore.BLACK + Back.WHITE, "Sigma Rule:", Style.RESET_ALL)
    print(rule)
    print("")

    # Write an output file
    if args.o:
        with open(args.o, "w") as fh:
            fh.write(rule)

