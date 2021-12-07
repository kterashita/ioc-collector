#!/usr/bin/env python3

import re
import argparse
import json
import yaml
import requests

init_yaml_filename = "config.yaml.init"

def get_argparse():
    parser = argparse.ArgumentParser(
        description="Help text of this command."
    )
    parser.add_argument('--init', action='store_true', help="initalize config.yaml.init")
    parser.add_argument('--urlscanio', action='store_true', help="urlscan.io submit")
    parser.add_argument('--twitter', action='store_true', help="twitter search")
    parser.add_argument('-c', '--config', type=str, required=False,
                        help="yaml file")
    parser.add_argument('-u', '--url', type=str, required=False,
                        help="url")
    return parser.parse_args()


def init_yaml():
    init_yaml = {
        'twitter':
            {
                'apikey': "",
                'apikeysecret': "",
                'accesstoken': "",
                'accesstokensecret': "",
                'bearer': "",
                'keywords': [
                    "",
                    ""
                ]
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


def run_urlscanio_one(args, config_dict):
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


def run_urlscanio_batch(batch_list, config_dict):
    #
    # Ref: https://urlscan.io/docs/api/
    #
    headers = {
        'API-Key': config_dict['urlscanio']['apikey'],
        'Content-Type': 'application/json'
        }
    for url in batch_list:
        data = {
            "url": url,
            "visibility": "public"
            }
        response = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            data=json.dumps(data)
            )
        print(response.json())


def run_twitter(args, config_dict):
    headers = {
        "Authorization": "Bearer {}".format(config_dict['twitter']['bearer'])
    }
    url = "https://api.twitter.com/2/tweets/search/recent"
    params_len = len(config_dict['twitter']['keywords'])

    result = []
    results = []
    results_all = []

    for j in range(params_len):
        results = []
        params = {'query': config_dict['twitter']['keywords'][j]}
        r = requests.get(url, headers=headers, params=params)
        tweets = r.json()
                # print(json.dumps(tweets, indent=4))
        for i in range(tweets['meta']['result_count']):
            result = []
            tweet = tweets['data'][i]['text']
            tweet = re.sub('IP:', '', tweet)
            tweet = re.sub(';', '', tweet)
            for line in tweet.split():
                if re.search('\.', line):
                    if re.search('t.co', line) is None:
                        result.append(line)
            results.extend(result)
        results_all.extend(results)
    return set(list(results_all))  # list


def main():
    args = get_argparse()
    if args.init:
        init_yaml()
    if args.config:
        config_dict = load_config(args)
    if args.urlscanio:
        run_urlscanio_one(args, config_dict)
    if args.twitter:
        run_urlscanio_batch(run_twitter(args, config_dict), config_dict)


if __name__ == '__main__':
    main()
