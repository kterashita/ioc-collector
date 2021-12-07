#!/usr/bin/env python3

import argparse
import json
import yaml
import requests

init_yaml_filename = "config.yaml.init"

def get_argparse():
    parser = argparse.ArgumentParser(
        description="Help text of this command."
    )
    parser.add_argument('--init', action='store_true')
    parser.add_argument('-c', '--config', type=str, required=False,
                        help="yaml file")
    parser.add_argument('-u', '--url', type=str, required=False,
                        help="url")
    return parser.parse_args()


def init_yaml():
    init_yaml = {
        'twitter':
            {
                'username': "", 'password': ""
                },
        'urlscanio':
            {
                'apikey': ""
            }
    }
    print("- Saved initial yaml config file: " + str(init_yaml_filename))
    with open(init_yaml_filename, 'w') as f:
        yaml.dump(init_yaml, f)


def load_config(args):
    with open(args.config, 'r') as f:
        config_yaml = yaml.safe_load(f)
        #
        # PyYAML yaml.load(input) Deprecation
        # https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
        #
        # print(config_yaml['urlscanio']['apikey'])
    return config_yaml


def run_urlscanio(args, config_dict):
    #
    # Ref: https://urlscan.io/docs/api/
    #
    headers = {
        'API-Key': config_dict['urlscanio']['apikey'],
        'Content-Type': 'application/json'
        }
    data = {
        "url": args.url,
        "visibility": "public"
        }
    response = requests.post(
        'https://urlscan.io/api/v1/scan/',
        headers=headers,
        data=json.dumps(data)
        )
    print(response)
    print(response.json())


def main():
    args = get_argparse()
    if args.init:
        init_yaml()
    if args.config:
        config_dict = load_config(args)
    run_urlscanio(args, config_dict)


if __name__ == '__main__':
    main()
