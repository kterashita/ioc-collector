#!/usr/bin/env python3

import os
import re
import time
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
    parser.add_argument('--urlscanioone', action='store_true', help="urlscan.io one submit")
    parser.add_argument('--urlscanioresult', action='store_true', help="urlscan.io result")
    parser.add_argument('-d', '--uuid', type=str, required=False, help="urlscan.io job uuid")
    parser.add_argument('--twitter', action='store_true', help="twitter search")
    parser.add_argument('--domainwatch', action='store_true', help="domainwatch search")
    parser.add_argument('-c', '--config', type=str, required=False,
                        help="yaml file")
    parser.add_argument('-u', '--url', type=str, required=False,
                        help="url")
    return parser.parse_args()


def init_yaml():
    init_yaml = {
        'twitter': {
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
        'urlscanio': {
            'apikey': ""
        },
        'domainwatch': {
            'quantity': 0,
            'keywords': [
                "",
                ""
            ]
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
    # print(response.json()['uuid'])


def run_urlscanio_batch(batch_list, config_dict):
    result_list = []
    #
    # Ref: https://urlscan.io/docs/api/
    #
    headers = {
        'API-Key': config_dict['urlscanio']['apikey'],
        'Content-Type': 'application/json'
        }
    api_url = "https://urlscan.io/api/v1/scan/"
    for url in batch_list:
        data = {
            "url": url,
            "visibility": "public"
            }
        response = requests.post(
            api_url,
            headers=headers,
            data=json.dumps(data)
            )
        print(response.json())
        try:
            result_list.append(response.json()['uuid'])
        except:
            pass
    #
    # output result after all submission
    #
    print("\033[31m- waiting jobs finish\033[0m")
    time.sleep(10)
    #
    # Ref: https://urlscan.io/docs/api/#result
    # > The most efficient approach would be to wait at least 10 seconds before starting to poll
    #
    for uuid in result_list:
        run_urlscanio_result(uuid, config_dict)  # output result


def run_urlscanio_result(uuid, config_dict):
    result_dir_name = "urlscanio_results"
    #
    # Ref: https://urlscan.io/docs/api/
    #
    headers = {
        'API-Key': config_dict['urlscanio']['apikey'],
        'Content-Type': 'application/json'
        }
    api_url = "https://urlscan.io/api/v1/result/"
    response = requests.get(
        api_url + uuid + "/",
        headers=headers,
        )
    response_dict = response.json()
    # print(json.dumps(response_json, indent=4))
    if not os.path.exists(result_dir_name):
        os.makedirs(result_dir_name)
    with open(result_dir_name + "/" + uuid + ".json", "w") as outfile:
        try:
            outfile.write(response_dict['page']['url'] + ": " + response_dict['verdicts']['overall']['brands'][0])
        except:
            pass


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
                    if re.search("t.co|virustotal.com", line) is None:
                        result.append(line)
            results.extend(result)
        results_all.extend(results)
    return set(list(results_all))  # list


def run_domainwatch(args, config_dict):
    api_url = "https://domainwat.ch/api/search?type=whois&"
    headers = {
        'Content-Type': 'application/json'
        }
    results_list = []

    for j in range(len(config_dict['domainwatch']['keywords'])):
        query = config_dict['domainwatch']['keywords'][j]
        print("\033[31mkeyword: " + config_dict['domainwatch']['keywords'][j] + "\033[0m")
        response = requests.get(
            api_url + query,
            headers=headers,
            )
        response_json = response.json()        
        for i in range(config_dict['domainwatch']['quantity']):
            results_list.append(response_json['results'][i]['domain'])
            print("\033[31mdomain: " + response_json['results'][i]['domain'] + "\033[0m")

    return set(results_list)


def main():
    args = get_argparse()
    if args.init:
        init_yaml()
    if args.config:
        config_dict = load_config(args)
    if args.urlscanioone:
        run_urlscanio_one(args, config_dict)
    if args.urlscanioresult:
        run_urlscanio_result(args, config_dict)
    if args.twitter:
        run_urlscanio_batch(run_twitter(args, config_dict), config_dict)
    if args.domainwatch:
        run_urlscanio_batch(run_domainwatch(args, config_dict), config_dict)


if __name__ == '__main__':
    main()
