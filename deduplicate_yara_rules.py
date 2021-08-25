"""
BASED ON WORK FROM https://github.com/marirs/dedupe_yara_rule
From Author: marirs
"""

import sys
import io
import os
from collections import defaultdict
try:
    import re2 as re
except ImportError:
    import re


all_imports = set()
all_yara_rules = set()
rule_names = set()
rule_dict = defaultdict(list)
yara_rule_regex = r"(^[\s+private\/\*]*rule\s[0-9a-zA-Z_\@\#\$\%\^\&\(\)\-\=\:\s]+\{.*?condition.*?\s\})"
comments_regex = r"(/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/|^//.*?$)"
imports_regex = r"(^import\s+.*?$)"
rules_re = re.compile(yara_rule_regex, re.MULTILINE | re.DOTALL)
import_re = re.compile(imports_regex, re.MULTILINE | re.DOTALL)
comments_re = re.compile(comments_regex, re.MULTILINE | re.DOTALL)
verbose = False

def extract(yara_file):
    """
    Extracts rules, commented rules and imports from a given yara file
    :param yara_file: Yara file
    :return: tuple (list of imports/None, list of yara rules/None, list of commented yara rules/None)
    """
    content = None
    yara_rules = []
    commented_yar_rules = []
    imports = []
    result_tuple = None
    encodings = ['utf-8', 'cp1252', 'windows-1250', 'windows-1252', 'ascii']
    for e in encodings:
        sys.stdout.flush()
        with io.open(yara_file, "r", encoding=e) as rule_file:
            # Read from rule file
            try:
                content = rule_file.read()
                break
            except Exception as err:
                sys.stdout.write("\n[!] {}: {}".format(yara_file, err))
                if encodings.index(e) + 1 < len(encodings):
                    sys.stdout.write(
                        "\n -> trying codec: {} for {}".format(encodings[encodings.index(e) + 1], yara_file))
                else:
                    sys.stdout.write("\n[!] No codec matched to open {}".format(yara_file))
                content = None

    if not content:
        return (None, None, None)

    yara_rules = rules_re.findall(content)
    if verbose:
        sys.stdout.write("\n[{:>5} rules] {}".format(len(yara_rules), yara_file))
        sys.stdout.flush()

    if yara_rules:
        # clean 'em
        yara_rules = [rule.strip().strip("*/").strip().strip("/*").strip() for rule in yara_rules]
        # we have some yara rules in this file
        # lets check for comments or commented rules & the imports
        # in this rule file
        imports = import_re.findall(content)
        commented_yar_rules = comments_re.findall(content)

        if commented_yar_rules:
            commented_yar_rules = [_f for _f in [comments for sub in commented_yar_rules for comments in sub if
                                                 comments.strip().startswith(("/*", "//"))] if _f]
            # remove commented yara rules
            yara_rules = [x for x in yara_rules if x not in "".join(commented_yar_rules)]

    result_tuple = (imports, yara_rules, commented_yar_rules)
    return result_tuple


def dedupe(yara_rule_file, out_yara_deduped_rule_file):
    """
    dedupe yara rules and store the unique ones in the output directory
    :param yara_rules_path: path to where yara rules are present
    :param yara_output_path: path to where deduped yara rules are written
    :return:
    """
    global rule_names
    global all_imports
    global all_yara_rules
    global rule_dict

    # go over all the yara rule file and process it
    sys.stdout.flush()
    deduped_content = ""

    imports, yar_rules, commented_yar_rules = extract(yara_rule_file)
    if not imports and not yar_rules and not commented_yar_rules:
        return

    if imports:
        # we found some imports
        all_imports.update(imports)
        deduped_content = "".join(imports) + "\n" * 3

    if yar_rules:
        for rule in yar_rules:
            rulename = rule.strip().splitlines()[0].strip().partition("{")[0].strip()
            rulename = rule.split(":")[0].strip() if ":" in rulename else rulename
            rule_dict[rulename].append(yara_rule_file)

            if rulename not in rule_names:
                deduped_content += "".join(rule.strip()) + "\n" * 2
                rule_names.add(rulename)
                all_yara_rules.add("\n// rule from: {}\n".format(yara_rule_file) + rule.strip() + "\n")

        # write the deduped rule to file
        with io.open(out_yara_deduped_rule_file, 'wb') as f:
            f.write(deduped_content.encode())
