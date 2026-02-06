# Standard
import argparse
import os
import tomllib
import sys
import logging

# Third-party
from splunklib import client, binding

# Setting Up Logger
logging.basicConfig(level=logging.INFO)

def connect_to_splunk(host: str, port: int, username: str, password: str, app: str) -> client.Service:
    """Creates a connection to a Splunk instance.

    Args:
        host (str): IP Address Of The Splunk Instance.
        port (int): The Splunk Management Port.
        username (str): The User Used For Authenticating To The Splunk Instance.
        password (str): The Password Used For Authenticating To The Splunk Instance.
        app (str): The Splunk App Name Used For Detection as Code.

    Returns:
        service: An initialized Service connection. 
    """

    try:
        service = client.connect(host=host, port=port, username=username, password=password, app=app)
        if service:
            logging.debug("Splunk service connection created successfully")
    except binding.AuthenticationError:
        logging.error("Auth error")
        sys.exit(1)
    return service


def upload_rules(service: client.Service, app: str) -> None:
    """
    Walks through a directory named "rules", reads TOML files (each representing a detection rule),
    and for each rule, it deletes any existing version in Splunk before uploading the updated rule definition.

    Requires a "rules" directory in the same directory as the script, containing TOML files
    with the detection rule definitions.

    Args:
        service (client.Service): A Splunk Connection Instance.
        app (str): The Splunk App Name Used For Detection as Code.

    Returns:
        None: This function does not return a value.

    """
    failed_check_exists = False
    failed_rule_filenames = []
    successful_rule_filenames = []
    # The Collection containing the SavedSearch entities.
    saved_search_collection = service.saved_searches
    # Iterating through the rules directory.
    for root, _, files in os.walk("rules"):
        for file in files:
            if file.endswith(".toml"):
                try:
                    logging.info('Opening %s', file)
                    file_path = os.path.join(root, file)
                    logging.info("Loading File %s", file)
                    with open(file_path, "rb") as toml:
                        # Loading the toml file.
                        rule = tomllib.load(toml)
                        # Building the rule.
                        current_rule_name = rule["rule"]["name"]
                        description = rule["rule"]["description"]
                        authors = ", ".join(rule["rule"]["author"])
                        logging.info("Processing Rule %s", current_rule_name)
                        if current_rule_name in saved_search_collection:
                            logging.debug("Updating Rule")
                            rule_params = {
                                "actions": ["alert_manager"],
                                "action.alert_manager": "1",
                                "action.alert_manager.param.append_incident": "0",
                                "action.alert_manager.param.auto_previous_resolve": "0",
                                "action.alert_manager.param.auto_subsequent_resolve": "0",
                                "action.alert_manager.param.auto_suppress_resolve": "0",
                                "action.alert_manager.param.auto_ttl_resove": "0",
                                "action.alert_manager.param.impact": rule["splunk"]["impact"],
                                "action.alert_manager.param.title": current_rule_name,
                                "action.alert_manager.param.urgency": rule["splunk"]["urgency"],
                                "action.webhook.enable_allowlist": "0",
                                "alert.suppress": "0",
                                "alert.track": "1",
                                "cron_schedule": "*/5 * * * *",
                                "description": f"{description}\nThis rule is part of the Detection-as-Code ruleset.\nAuthors: {authors}", 
                                "dispatch.earliest_time": "-5m",
                                "dispatch.latest_time": "now",
                                "is_scheduled": "1",
                                "request.ui_dispatch_app": app,
                            }
                            saved_search_collection[current_rule_name].update(**rule_params)
                            successful_rule_filenames.append(file)
                        if current_rule_name not in saved_search_collection:
                            search=rule["splunk"]["query"]
                            search_params = {
                                "actions": ["alert_manager"],
                                "action.alert_manager": "1",
                                "action.alert_manager.param.append_incident": "0",
                                "action.alert_manager.param.auto_previous_resolve": "0",
                                "action.alert_manager.param.auto_subsequent_resolve": "0",
                                "action.alert_manager.param.auto_suppress_resolve": "0",
                                "action.alert_manager.param.auto_ttl_resove": "0",
                                "action.alert_manager.param.impact": rule["splunk"]["impact"],
                                "action.alert_manager.param.title": current_rule_name,
                                "action.alert_manager.param.urgency": rule["splunk"]["urgency"],
                                "action.webhook.enable_allowlist": "0",
                                "alert.suppress": "0",
                                "alert.track": "1",
                                "cron_schedule": "*/5 * * * *",
                                "description": f"{description}\nThis rule is part of the Detection-as-Code ruleset.\nAuthors: {authors}", 
                                "dispatch.earliest_time": "-5m",
                                "dispatch.latest_time": "now",
                                "is_scheduled": "1",
                                "request.ui_dispatch_app": app,
                            }
                            # We add our rule to the saved_search_collection
                            logging.info("Creating Rule")
                            saved_search_collection.create(current_rule_name,search,**search_params)
                            successful_rule_filenames.append(file)
                except FileNotFoundError:
                    logging.error("File not found: %s", file)
                    failed_check_exists = True
                    failed_rule_filenames.append(file)
                except IOError:
                    logging.error(
                        "Cannot read file: %s", file)
                    failed_check_exists = True
                    failed_rule_filenames.append(file)
                except tomllib.TOMLDecodeError:
                    logging.error(
                        "Unable to parse TOML: %s", file)
                    failed_check_exists = True
                    failed_rule_filenames.append(file)

    logging.info("Validation over.\n")
    logging.info(f"Uploaded files:\n{successful_rule_filenames}")
    if failed_check_exists:
        logging.info(f"Files with errors:\n{failed_rule_filenames}")

# Main function


def main():
    """
    Uploads detection rules using Splunk SDK.

    Command-line arguments:
        --ip: IP Address Of The Splunk Instance.
        --port: The Splunk Management Port.
        --app: The Splunk App Name Used For Detection as Code.
        --user: The User Used For Authenticating To The Splunk Instance.
        --password: The Password Used For Authenticating To The Splunk Instance
    Defaults:
        port: 8089
    Example usage:
        python splunk_uploader.py --ip IP_ADDRESS --user USER --password PASSWORD --app APP
    Requires:
        * splunk-sdk python package
    """

    # Defining program arguments.
    parser = argparse.ArgumentParser(
        prog='Splunk Uploader',
        description='BC-DaC Uploader Script For Splunk Instances.')
    parser.add_argument(
        '--ip',
        help='IP Address Of The Splunk Instance',
        required=True)
    parser.add_argument(
        '--port',
        help='The Splunk Management Port',
        required=False,
        default="8089")
    parser.add_argument(
        '--user',
        help='The User Used For Authenticating To The Splunk Instance',
        required=True)
    parser.add_argument(
        '--password',
        help='The Password Used For Authenticating To The Splunk Instance',
        required=True)
    parser.add_argument(
        '--app',
        help='The Splunk App Name Used For Detection as Code.',
        required=True)
    args = parser.parse_args()

    # Creating The Service Object.
    service = connect_to_splunk(args.ip, args.port, args.user, args.password, args.app)
    if service:
        # If the Service Object exists pass it to the upload_rules function.
        upload_rules(service, args.app)


if __name__ == "__main__":
    main()

