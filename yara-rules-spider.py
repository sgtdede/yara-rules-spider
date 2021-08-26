import argparse
from helpers import is_running_standalone, get_default_root
from os.path import join, isfile, basename
from os import makedirs, scandir
from deduplicate_yara_rules import dedupe
import shutil
import yara
import zipfile
import requests
import logging
import io
import re

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',)
logger = logging.getLogger(__name__)

YARA_RULES_REPOS = [
    "https://github.com/Neo23x0/signature-base/archive/master.zip",
    "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip",
    "https://github.com/eset/malware-ioc/archive/refs/heads/master.zip",
    "https://raw.githubusercontent.com/fireeye/red_team_tool_countermeasures/master/all-yara.yar"
]

parser = argparse.ArgumentParser(description='Yara rules aggregator/spider tool')
parser.add_argument(dest='repositories',metavar='repositories', default=YARA_RULES_REPOS, nargs='*')
parser.add_argument('-v', dest='verbose', action='store_true', help='verbose mode')
args = parser.parse_args()

if args.verbose:
    logger.setLevel(logging.DEBUG)

rules_root_path = join(get_default_root(), "rules")
zip_extraction_root_path = join(get_default_root(), "raw-rules")
makedirs(rules_root_path, exist_ok=True)
makedirs(zip_extraction_root_path, exist_ok=True)

URL_REGEXP=re.compile(r"https?://[a-zA-Z0-9.]+/(\w+)/.+")

def spider(yara_rules_repositories):
    """
    Fetch and parse all yara files from remote repository and store all yara files locally ordered by their corresponding repo
    """
    for yara_rules_repo in yara_rules_repositories:
        if yara_rules_repo.startswith("https://") or yara_rules_repo.startswith("http://"):
            logger.info(f"Fetching yara rules from {yara_rules_repo}")
            repo_name = URL_REGEXP.search(yara_rules_repo).group(1)
            repo_path = join(zip_extraction_root_path, repo_name)
            makedirs(repo_path, exist_ok=True)
            req = requests.get(yara_rules_repo)

            if yara_rules_repo.endswith(".zip"):
                zip_file = zipfile.ZipFile(io.BytesIO(req.content))
                for zip_file_path in zip_file.namelist():
                    if zip_file_path.endswith(".yar") or zip_file_path.endswith(".yara"):
                        sig_name = basename(zip_file_path)
                        with zip_file.open(zip_file_path) as zf, open(join(repo_path, sig_name), 'wb') as df:
                            shutil.copyfileobj(zf, df)

            elif yara_rules_repo.endswith(".yar") or yara_rules_repo.endswith(".yara"):
                with open(join(repo_path, f"{repo_name}.yar"), 'wb') as df:
                    df.write(req.content)

            else:
                logger.warning(f"Cannot parse rules from {yara_rules_repo}: invalid format (only .yar .yara and .zip extensions supported)")
                continue

        else:
            logger.warning(f"Cannot fetch rules from {yara_rules_repo}: invalid format")


def concat_rules(raw_rules_path, compile=True):
    """
    Concat all rules from a folder into a global one
    """
    repo_name = basename(raw_rules_path)
    rule_files = [rule_file.path for rule_file in scandir(raw_rules_path)]
    full_rule_path = join(rules_root_path, repo_name)
    full_yara_rule_file_path = join(full_rule_path, "all.yar")
    full_compiled_rule_file_path = join(full_rule_path, "all.compiled")
    makedirs(full_rule_path, exist_ok=True)
    with open(full_yara_rule_file_path,'wb') as afd:
        for rule_file in scandir(raw_rules_path):
            logger.debug(f"copying {rule_file.path} to {full_yara_rule_file_path}")
            with open(rule_file.path,'rb') as rfd:
                shutil.copyfileobj(rfd, afd)
                afd.write(b"\n")

    if compile:
        logger.info(f"loading yara rule file {full_yara_rule_file_path}...")
        repo_rules = yara.compile(full_yara_rule_file_path, externals= {'filename': '', 'filetype': '', 'filepath': '', 'extension': ''})
        logger.info(f"saving compiled yara rule file into {full_compiled_rule_file_path}")
        repo_rules.save(full_compiled_rule_file_path)

    return full_yara_rule_file_path


def one_rule_to_rule_them_all(compile=True):
    repositories_full_yara_rule_files = []
    ultimate_yara_rule_path = join(rules_root_path, "all_with_dup.yar")
    ultimate_yara_rule_clean_path = join(rules_root_path, "all.yar")
    ultimate_compiled_rule_path = join(rules_root_path, "all.compiled")

    # generate global rule file for all repos
    for rule_repo in scandir(zip_extraction_root_path):
        logger.info(f"concat rules for repo {basename(rule_repo.path)}")
        repositories_full_yara_rule_files.append(concat_rules(rule_repo.path, compile))

    with open(ultimate_yara_rule_path,'wb') as ufd:
        for full_repo_rule_file in repositories_full_yara_rule_files:
            logger.info(f"copying {full_repo_rule_file} to {ultimate_yara_rule_path}")
            with open(full_repo_rule_file,'rb') as rfd:
                shutil.copyfileobj(rfd, ufd)
                ufd.write(b"\n")

    dedupe(ultimate_yara_rule_path, ultimate_yara_rule_clean_path)

    if compile:
        logger.info(f"loading yara rule file {ultimate_yara_rule_clean_path}...")
        repo_rules = yara.compile(ultimate_yara_rule_clean_path, externals= {'filename': '', 'filetype': '', 'filepath': '', 'extension': ''})
        logger.info(f"saving compiled yara rule file into {ultimate_compiled_rule_path}")
        repo_rules.save(ultimate_compiled_rule_path)


def main():
    spider(args.repositories)
    one_rule_to_rule_them_all()


if __name__ == "__main__":
    main()
