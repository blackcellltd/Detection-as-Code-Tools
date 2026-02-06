"""
This Python script automates the upload of detection rules using the Kibana Detection API.

Parameters:
    kibanaIP (str): The IP address of the Kibana instance.
    elasticApiKey (str): The Elastic API key for authentication.
    port (str): The port of the Kibana service.
"""

import argparse
import json
import logging
import os
import tomllib
import sys

import requests

logging.basicConfig(level=logging.INFO)


def main():
    """
    Uploads detection rules using the Kibana Detection API.
    This script iterates through a directory named "rules", reads TOML files representing detection rules, 
    and handles the deployment of new rules as well as updates to existing ones.

    Command-line arguments:
        kibana_ip: The IP address of the Kibana instance.
        elastic_api_key: The Elastic API key for authentication.
        port: The port of the Kibana service.

    The script logs successful and unsuccessful uploads.  Unsuccessful uploads include the error message
    returned by the API.

    Requires a "rules" directory in the same directory as the script, containing TOML files
    with the detection rule definitions.
    """


    # Defining program arguments.
    parser = argparse.ArgumentParser(
        prog='Elastic Uploader',
        description='BC-DaC Uploader Script For Elastic Instances.')
    parser.add_argument(
        '--ip',
        help='IP Address Of The Kibana Instance',
        required=True)
    parser.add_argument(
        '--apikey',
        help='The API Key Used For Authenticating To The Elastic Instance',
        required=True)
    parser.add_argument(
        '--port',
        help='The Kibana Management Port',
        required=False,
        default="5601")
    args = parser.parse_args()

    kibana_ip=args.ip
    elastic_api_key=args.apikey
    kibana_port=args.port
    kibana_url = "https://" + kibana_ip + ":"+kibana_port+"/api/detection_engine/rules"

    request_header = {
        'Content-Type': 'application/json;charset=UTF-8',
        'elastic-api-version': '2023-10-31',
        'kbn-xsrf': 'true',
        'Authorization': 'ApiKey ' + elastic_api_key
    }

    successful_uploads = []
    unsuccessful_uploads = {}

    for root, _, files in os.walk("rules"):
        for file in files:
            if file.endswith(".toml"):

                logging.debug('Opening %s', file)
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as toml:
                    alert_rule = tomllib.load(toml)["rule"]
                    alert_rule_json = json.dumps(alert_rule, indent=None)

                kibana_url_with_rule_id = kibana_url + "?rule_id=" + alert_rule['rule_id']
                putResponse = requests.put(kibana_url_with_rule_id, headers=request_header, data=alert_rule_json, verify=False)
                if putResponse.status_code == requests.codes.ok:
                    successful_uploads.append(alert_rule['name'])
                elif putResponse.status_code == requests.codes.not_found:
                    postResponse = requests.post(kibana_url_with_rule_id, headers=request_header, data=alert_rule_json, verify=False)
                    if postResponse.status_code == requests.codes.ok:
                        successful_uploads.append(alert_rule['name'])
                    else:
                        unsuccessful_uploads.update({alert_rule['name']: postResponse.text})
                else:
                    unsuccessful_uploads.update({alert_rule['name']: putResponse.text})
    logging.info("Successful uploads: %s", successful_uploads)
    logging.info("Unsuccessful uploads: %s", unsuccessful_uploads)


if __name__ == '__main__':
    main()
