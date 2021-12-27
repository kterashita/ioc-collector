#!/usr/bin/env python3

import os
import re
import time
from datetime import datetime, timedelta
import argparse
import json
from requests import api
import yaml
import requests
import ipaddress
from tqdm import tqdm
# virustotal_intelsearch()
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import chromedriver_binary
# from webdriver_manager.chrome import ChromeDriverManager


init_yaml_filename = "config.yaml.init"

def get_argparse():
    parser = argparse.ArgumentParser(
        description="Help text of this command."
    )
    parser.add_argument('--init', action='store_true', help="initalize config.yaml.init")
    parser.add_argument('--urlscanioone', action='store_true', help="urlscan.io one submit")
    parser.add_argument('--urlscanioresult', action='store_true', help="urlscan.io result")
    parser.add_argument('--virustotal', action='store_true', help="virustotal test")
    parser.add_argument('-d', '--uuid', type=str, required=False, help="urlscan.io job uuid")
    parser.add_argument('--twitter', action='store_true', help="twitter search")
    parser.add_argument('--twitterip', action='store_true', help="twitter ip search")
    parser.add_argument('--domainwatch', action='store_true', help="domainwatch search")
    parser.add_argument('--vtsearchicon', action='store_true', help="virustotal intel search")
    parser.add_argument('--teams', action='store_true', help="teams call")
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
        },
        'virustotal': {
            'apikey': "",
            'icon_dhash': [
                "",
                ""
            ]
        },
        'teams': {
            'webhook_url': ""
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
    """
    flow chart
        import batch_list is default list to scan
        enrich on batch_list_enrich which is added ip_resolve result of IP address in the batch_list
        run loop urlscan with batch_list_enrich
    """
    #
    # Ref: https://urlscan.io/docs/api/
    #
    result_list = []

    headers = {
        'API-Key': config_dict['urlscanio']['apikey'],
        'Content-Type': 'application/json'
        }
    api_url = "https://urlscan.io/api/v1/scan/"

    # Indicator
    print("\033[31m# Run: urlscanuio_batch()" + "\033[0m")
    print("\033[31m# input iocs: " + str(len(batch_list)) + "\033[0m")

    # Indicator
    print("\033[31m# Enrich: virustotal_ip_resolve()" + "\033[0m")
    batch_list_enrich = batch_list
    for batch in batch_list:  # needs to be tqdm-ed, instad of vt()
        try:
            ip = ipaddress.ip_address(batch)
            batch_list_enrich.extend(run_virustotal_ip_resolve(str(ip), config_dict))
        except:
            pass

    print("\033[31m# urlscan.io api call count with vt enrichment: " + str(len(batch_list_enrich)) + "\033[0m")

    for i_tqdm in tqdm(range(len(batch_list_enrich))):
        data = {
            "url": batch_list_enrich[i_tqdm],
            "visibility": "public"
            }
        response = requests.post(
            api_url,
            headers=headers,
            data=json.dumps(data)
            )
        # print(response.json())
        try:
            result_list.append(response.json()['uuid'])
        except:
            pass
    #
    # output result after all submission
    #
    # print("\033[31m- waiting jobs finish\033[0m")
    # time.sleep(10)
    #
    # Ref: https://urlscan.io/docs/api/#result
    # > The most efficient approach would be to wait at least 10 seconds before starting to poll
    #

    # for uuid in result_list:
    #     run_urlscanio_result(uuid, config_dict)  # output result
    print("\033[31m# Output results of scceeeded queries into local files \033[0m")
    for i in tqdm(range(len(result_list))):
        run_urlscanio_result(result_list[i], config_dict)  # output result


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
        api_url + str(uuid) + "/",
        headers=headers,
        )
    response_dict = response.json()
    # print(json.dumps(response_json, indent=4))
    if not os.path.exists(result_dir_name):
        os.makedirs(result_dir_name)
    
    success_list = []  # to output only success result to stdout
    with open(result_dir_name + "/" + uuid + ".json", "w") as outfile:
        try:
            outfile.write(response_dict['page']['url'] + ": " + response_dict['verdicts']['overall']['brands'][0])
            success_list.append([response_dict['page']['url'], response_dict['verdicts']['overall']['brands'][0]])
            # Notify to MS Teams channel
            notify_text = uuid + " " + response_dict['verdicts']['overall']['brands'][0]
            notify_teams(notify_text, config_dict)
        except:
            pass
    # for success_result in success_list:
        # print(success_result[0], success_result[1])


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
        # Indicator
        print("\033[31m# Twitter Keyword Pattern:" + config_dict['twitter']['keywords'][j] + "\033[0m")
        for i in range(tweets['meta']['result_count']):
            result = []
            tweet = tweets['data'][i]['text']
            tweet = re.sub('IP:', ' ', tweet)
            tweet = re.sub('\[', '', tweet)
            tweet = re.sub('\]', '', tweet)
            tweet = re.sub(';', ' ', tweet)
            for line in tweet.split():
                if re.search('\.', line):
                    if re.search("t.co|virustotal.com|…", line) is None:
                        result.append(line)
            results.extend(result)
        print("\033[31m  # Hit count before merge:" + str(len(results)) + "\033[0m")
        results_all.extend(results)
    return list(set(results_all))  # list


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

    return list(set(results_list))


def run_virustotal_ip_resolve(ip, config_dict):
    """
    expected input:
        ip:
            - resolve target,
            - ip address,
            - str
    expected output:
        return:
            - resolved recent urls upto specified limit,
            - list
    """
    # print("\033[31m# Run: virustotal_ip_resolve() \033[0m")
    #
    # Ref: https://developers.virustotal.com/reference/ip-relationships
    #
    api_url = "https://www.virustotal.com/api/v3/ip_addresses/"
    api_ip = ip
    api_limit = "/urls?limit=10"  # the limit should be revised if the total exceeds the urlscan.io api limit
    result_list = []

    headers = {
        'Accept': 'application/json',
        'x-apikey' : config_dict['virustotal']['apikey']
        }
    response = requests.get(
        api_url + api_ip + api_limit,
        headers=headers
        )
    response_dict = response.json()

    for i in tqdm(range(len(response_dict['data']))):
        # print("\033[31m# URL " + str(i) + ": " + str(response_dict['data'][i]['attributes']['url']) + "\033[0m")
        result_list.append(str(response_dict['data'][i]['attributes']['url']))
    
    #
    print(result_list)
    #
    return result_list  # list


def virustotal_selenium(query, config_dict):
    """
    expected input:
        query:
            - entity:url main_icon_dhash:HASH,
            - entity:domain main_icon_dhash:HASH
    process:
        modules:
            - selenium
            - bs4
    expected output:
        return:
            - found urls or domains,
            - list
    """
    # webdriver_path = "/usr/local/lib/python3.8/site-packages/chromedriver_binary/chromedriver"
    # print(os.environ["PATH"])
    # print(ChromeDriverManager().install())
    url = "https://www.virustotal.com/api/v3/intelligence/search"

    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-gpu')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument("--window-size=1920,1080")
    driver = webdriver.Chrome(options=options)
    # driver = webdriver.Chrome(executable_path=ChromeDriverManager().install(), options=options)
    # driver = webdriver.Chrome()
    # driver = webdriver.Chrome(executable_path=webdriver_path, chrome_options=options)
    driver.get(url)
    
    print(driver.title)
    driver.close()
    driver.quit()


def vt_search_icon(config_dict):
    """
    expected input:
        dhash:
            - icon data dhash
    expected output:
        return:
            - list
    
    flow chart
        vt api calling
            <- response
                ['data'][0]['id'] = domain
                append only first response into result_list
                ['links']['next'] = url of next page for next 10 results
            for loop by recursive to get after sedond result
                result_list <- 10 domains, recursive times
            return result_list
    """
    # print("\033[31m# Run: virustotal_ip_resolve() \033[0m")
    #
    # Ref: https://developers.virustotal.com/reference/ip-relationships
    # Ref: https://github.com/VirusTotal/vt-py/blob/master/examples/search.py
    api_url = "https://www.virustotal.com/api/v3/intelligence/search"
    search_date_range = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

    result_list = []

    headers = {
        'Accept': 'application/json',
        'x-apikey' : config_dict['virustotal']['apikey']
        }
    
    recurusive = 3  # one request contains 10 results. recursive=2 gets 20 results.

    # make query parameter fron config
    query_icon = ""
    for x in config_dict['virustotal']['icon_dhash']:
        query_icon = query_icon + "main_icon_dhash:%s OR " % x
    query_icon = re.sub(' OR $', '', query_icon)
    query = 'entity:domain ( creation_date:"%s+" OR last_update_date:"%s+" ) (%s)' % (search_date_range, search_date_range, query_icon)
    params = {
        'query': query
    }

    # call vt api
    response = requests.get(
        api_url,
        headers=headers,
        params=params,
        )
    response_dict = response.json()

    for i in tqdm(range(len(response_dict['data'])), ascii=True, desc="1     "):
        result_list.append(response_dict['data'][i]['id'])
        # append subject anlternative names
        try:
            result_list.extend(response_dict['data'][i]['attributes']['last_https_certificate']['extensions']['subject_alternative_name'])
        except:
            pass
    for i in tqdm(range(recurusive - 1), ascii=True, desc="2 to %s" % recurusive):
        try:
            url_next = response_dict['links']['next']
            response = requests.get(
                url_next,
                headers=headers,
                )
            response_dict = response.json()
            for i in (range(len(response_dict['data']))):
                result_list.append(response_dict['data'][i]['id'])
                # append subject anlternative names
                try:
                    result_list.extend(response_dict['data'][i]['attributes']['last_https_certificate']['extensions']['subject_alternative_name'])
                except:
                    pass
        except:
            pass
        
    return list(set(result_list))
    """
    for i in (range(len(response_dict['data']))):
        print(response_dict['data'][i]['id'])
    
    print(response_dict['links']['next'])

    url_next = response_dict['links']['next']
    response = requests.get(
        url_next,
        headers=headers,
        )
    response_dict = response.json()
    for i in (range(len(response_dict['data']))):
        print(response_dict['data'][i]['id'])
    """


def notify_teams(notify_text, config_dict):
    api_url = config_dict['teams']['webhook_url']
    notify_text = "api test"
    notify_title = "urlscan.io result"

    headers = {
        'Content-Type': 'application/json'
        }

    post_json = json.dumps(
        {
            'title': notify_title,
            'text': notify_text
        }
    )

    requests.post(
        api_url,
        post_json
        )

    print("\033[31m# Run: notify_teams()" + "\033[0m")

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
    if args.virustotal:
        run_virustotal_ip_resolve("1.1.1.1", config_dict)  # option for test
    if args.vtsearchicon:
        run_urlscanio_batch(vt_search_icon(config_dict), config_dict)
    if args.twitterip:  # now testing
        """
        test_lists = run_twitter(args, config_dict)
        test_ip_list = []
        for test_list in test_lists:
            try:
                ip = ipaddress.ip_address(test_list)
                test_ip_list.append(test_list)
            except:
                pass
        print(test_ip_list)
        """
    if args.teams:
        notify_teams("text", config_dict)


if __name__ == '__main__':
    main()
