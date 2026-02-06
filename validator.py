"""
This script validates a directory of rule files (TOML format) against
    specified patterns and requirements.
"""

import tomllib
import sys
import logging
import os
import re
import argparse

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

requiredMetadataTableFields = [
    "creation_date",
    "maturity"
]
requiredRuleTableFields = [
    "author",
    "description",
    "name",
    "risk_score",
    "severity",
    "type",
    "rule_id",
    "language",
    "query",
    "threat",
]
MATURITY_LEVELS = [
    'development',
    'experimental',
    'beta',
    'production',
    'deprecated'
]
OS_OPTIONS = [
    'windows',
    'linux',
    'macos'
]
LANGUAGES = [
    'eql',
    'esql',
    'kuery',
    'lucene',
]

THREAT_FRAMEWORK = set([
    "MITRE ATT&CK",
])

REGEX_PATTERNS = {
    "date": r'^\d{4}/\d{2}/\d{2}$',
    "name": r'^[a-zA-Z0-9].+?[a-zA-Z0-9()]$',
    "pr": r'^$|\d+$',
    "sha256": r'^[a-fA-F0-9]{64}$',
    "uuid": r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    "tactic_id": r'^TA[0-9]+$',
    "tactic_reference": r'^https://attack.mitre.org/tactics/TA[0-9]+/$',
    "technique_id": r'^T[0-9]+$',
    "technique_reference": r'^https://attack.mitre.org/techniques/T[0-9]+/$',
    "subtechnique_id": r'^T[0-9]+.[0-9]+$',
    "subtechnique_reference": r'^https://attack.mitre.org/techniques/T[0-9]+/[0-9]+/$',
}

SEVERITY_LEVELS = {
    "critical": {"min": 74, "max": 100},
    "high": {"min": 48, "max": 73},
    "medium": {"min": 22, "max": 47},
    "low": {"min": 0, "max": 21},
}


def check_risk_score(severity: str, risk_score: int) -> str:
    """Verifies if the given risk score aligns with the severity level.

    Args:
        severity (str): Severity level.
        risk_score (int): Risk score.

    Returns:
        str: Describes the issue, or returns an empty string if no problem is found.
    """

    if severity in SEVERITY_LEVELS:
        if SEVERITY_LEVELS[severity]["min"] <= risk_score <= SEVERITY_LEVELS[severity]["max"]:
            return ""
        correct_range = f'{SEVERITY_LEVELS[severity]["min"]} <= {
            risk_score} <= {SEVERITY_LEVELS[severity]["max"]}'
        return f'''invalid risk_score range for severity
required range: {correct_range}'''
    return "invalid severity"


def reporter(
        file: str,
        problem: str,
        field: str,
        payload: str,
        details: str) -> str:
    """Generates a report message based on the provided parameters.

    Args:
        file (str): The name of the file.
        problem (str): The problem encountered.
        field (str): The field related to the problem.
        payload (str): Original content of the field.
        details (str): Detailed description of the problem.

    Returns:
        str: A formatted report message.

    Raises:
        ValueError: If a required variable is missing.
    """

    message = f'File: {file}\n'
    message += f'Problem: {problem}\n'
    message += f'Field: {field}\n'
    if payload != "":
        message += f'Payload: {payload}\n'
    if details != "":
        message += f'Details: {details}\n'
    return message


def summarize_errors(errors: list[str]) -> dict[str, int]:
    """Summarizes the error messages in a list.

    Args:
        errors (list): A list of error messages.

    Returns:
        dict: A dictionary mapping problem types to their respective counts.
    """

    summary = {}

    for error in errors:
        # Extract the problem type from the error message, removing leading/trailing whitespaces
        start = error.find("Problem: ") + len("Problem: ")
        end = error.find("\n", start)
        problem_type = error[start:end].strip()

        # Increment the count for this problem type
        if problem_type in summary:
            summary[problem_type] += 1
        else:
            summary[problem_type] = 1

    return summary


def validate(rules_directory: str):
    """Validates a directory of rule files against specified patterns and requirements.

    Args:
        rules_directory (str): The directory containing the rule files (TOML format).
            Defaults to "rules".

    Raises:
        SystemExit: Exits the program with an exit code of 1 if validation fails.
    """

    failure = False
    errors = []
    seen_rule_ids = set()
    if not rules_directory:
        rules_directory = "rules"
    rules = 0
    for _, _, files in os.walk(rules_directory):
        for file in files:
            if file.endswith(".toml"):
                rules += 1
                try:
                    with open(os.path.join(rules_directory, file), "rb") as f:
                        rule = tomllib.load(f)
                        f.close()
                except FileNotFoundError:
                    logging.error(
                        "File %s not found. It was probably deleted.", file)
                    continue
                except tomllib.TOMLDecodeError as e:
                    logging.error("Error reading file %s: %s", file, e)
                    errors.append(
                        reporter(
                            file=file,
                            problem="TOMLDecodeError",
                            field="",
                            payload=str(e),
                            details="File is not a valid TOML file"
                        )
                    )
                    failure = True
                    continue
                except Exception as e:
                    logging.error("Error reading file %s: %s", file, e)
                    continue

                logging.info('Checking: %s', file)

                # Check must required metadata fields
                for field in requiredMetadataTableFields:
                    if not field in rule["metadata"]:
                        errors.append(
                            reporter(
                                file=file,
                                problem="Missing [metadata]",
                                field=field,
                                payload="",
                                details="Field does not exist"
                            )
                        )
                        failure = True

                # Check must required rule fields
                for field in requiredRuleTableFields:
                    if not field in rule["rule"]:
                        errors.append(
                            reporter(
                                file=file,
                                problem="Missing [rule]",
                                field=field,
                                payload="",
                                details="Field does not exist"
                            )
                        )
                        failure = True

                # Check date format
                if not re.fullmatch(REGEX_PATTERNS["date"], rule["metadata"]["creation_date"]):
                    errors.append(
                        reporter(
                            file=file,
                            problem="Invalid [creation_date]",
                            field="creation_date",
                            payload=rule["metadata"]["creation_date"],
                            details=f'allowed regex: {REGEX_PATTERNS["date"]}'
                        )
                    )
                    failure = True

                # Check name format
                if not re.fullmatch(REGEX_PATTERNS["name"], rule["rule"]["name"]):
                    errors.append(
                        reporter(
                            file=file,
                            problem="Invalid [name]",
                            field="name",
                            payload=rule["rule"]["name"],
                            details=f'allowed regex: {REGEX_PATTERNS["name"]}'
                        )
                    )
                    failure = True

                # Check rule_id format
                if not re.fullmatch(REGEX_PATTERNS["uuid"], rule["rule"]["rule_id"]):
                    errors.append(
                        reporter(
                            file=file,
                            problem="Invalid [rule_id]",
                            field="rule_id",
                            payload=rule["rule"]["rule_id"],
                            details=f'allowed regex: {REGEX_PATTERNS["uuid"]}'
                        )
                    )
                    failure = True

                # Check maturity level
                if not rule["metadata"]["maturity"] in MATURITY_LEVELS:
                    errors.append(
                        reporter(
                            file=file,
                            problem="Invalid [maturity level]",
                            field="maturity",
                            payload=rule["metadata"]["maturity"],
                            details=f'allowed levels: {MATURITY_LEVELS}'
                        )
                    )
                    failure = True

                # Check rule language
                if not rule["rule"]["language"] in LANGUAGES:
                    errors.append(
                        reporter(
                            file=file,
                            problem="Invalid [language]",
                            field="language",
                            payload=rule["rule"]["language"],
                            details=f"allowed languages: {LANGUAGES}"
                        )
                    )
                    failure = True

                # Check severity level
                severity_error = check_risk_score(
                    rule["rule"]["severity"],
                    rule["rule"]["risk_score"]
                )
                if severity_error != "":
                    errors.append(
                        reporter(
                            file=file,
                            problem="Inconsistent [risk_score] range",
                            field="risk_score",
                            payload=f'{rule["rule"]["severity"]
                                       } / {rule["rule"]["risk_score"]}',
                            details=severity_error
                        )
                    )
                    failure = True

                # Check if rule_id is duplicated
                rule_id = rule["rule"]["rule_id"]
                if rule_id in seen_rule_ids:
                    errors.append(
                        reporter(
                            file=file,
                            problem="Duplicate [rule_id]",
                            field="rule_id",
                            payload=rule_id,
                            details="This rule_id has already been used in another rule"
                        )
                    )
                    failure = True
                else:
                    seen_rule_ids.add(rule_id)

                # Check note is exist
                if not rule["rule"]["note"]:
                    errors.append(
                        reporter(
                            file=file,
                            problem="Missing [note]",
                            field="note",
                            payload="",
                            details="Field does not exist or empty"
                        )
                    )
                    failure = True

                logging.info('Finished: %s', file)
            else:
                logging.info('Skipping: %s (not a TOML file)', file)
    if rules == 0:
        logging.info('No rules found')
        sys.exit(0)

    if failure:
        logging.info("\nValidation failed due to the following:\n")

        for e in errors:
            logging.info(e)
        logging.info("\n--------------------------------------")
        logging.info("--     Summary of problems found    --")
        summary = summarize_errors(errors)
        for problem_type, count in summary.items():
            logging.info(f"{problem_type}: {count} found")

        logging.info("\n--------------------------------------")
        logging.info("--    [!] Validation failed. [!]    --")
        logging.info("--------------------------------------")

        logging.info('Rule files found: %s', rules)
        logging.info('Problems found: %s', len(errors))
        sys.exit(1)
    else:
        logging.info("------------------------------------------")
        logging.info("--    [✓] Successful validation. [✓]    --")
        logging.info("------------------------------------------")
        logging.info('Rule files found: %s', rules)
        sys.exit(0)


def main():
    """Entry point for the detection ruleset validator.

    This script validates a directory of rule files (TOML format) against
        specified patterns and requirements.

    Raises:
        SystemExit: Exits the program with an appropriate exit code based on
            validation results.
    """

    parser = argparse.ArgumentParser(
        prog='Validator',
        description='Detection Ruleset Validator')

    parser.add_argument(
        '-d',
        '--directory',
        help='Rules directory',
        required=False,
        default="rules")

    args = parser.parse_args()

    logging.info("Starting validation...")
    validate(args.directory)


if __name__ == "__main__":
    main()
