#!/usr/bin/env python3

from modules import default, twitter, virustotal

import argparse
from tqdm import tqdm


def get_argparse():
    parser = argparse.ArgumentParser(
        description="Help text of this command."
    )
    parser.add_argument('--init', action='store_true', help="initalize config.yaml.init")
    parser.add_argument('-c', '--config', type=str, required=False, help="config yaml file")
    parser.add_argument('-a', '--action', type=str, required=False, help="action flag: [urlscan]")
    parser.add_argument('-s', '--source', type=str, required=False, help="source flag: [twitter]")
    return parser.parse_args()


def urlscan_twitter(args, config_dict):
    # get response from twitter search
    result_list = twitter.search(args, config_dict)
    # print(result_list)
    # output ${result_list} is list

    # enrich by virustotal ip resolve, call func with one by one
    result_list_enrich = []
    for x in tqdm(range(len(result_list)), desc='enrichment by vt'):
        enriched_text = virustotal.enrich_ip(result_list[x], config_dict)
        if type(enriched_text) is str:
            result_list_enrich.append(enriched_text)
        elif type(enriched_text) is list:
            result_list_enrich.extend(enriched_text)

    message = f'# Hit count after merge: {len(result_list_enrich)}.'
    print("\033[34m" + message + "\033[0m")
    # print(result_list_enrich)
    # output ${result_list_enrich} is list




def main():
    args = get_argparse()

    # individual option
    if args.init:
        default.init_config()
        exit()

    # a valid config file is must
    if args.config:
        config_dict = default.load_config(args)
    elif args.config is None:
        message = f'Please specify a valid config file with -c option.'
        print("\033[31m" + message + "\033[0m")
        exit()
    
    # action is urlscan, source is twitter
    if args.action == 'urlscan':
        if args.source == 'twitter':
            urlscan_twitter(args, config_dict)
        else:
            message = f'Please specify a valid -s option.'
            print("\033[31m" + message + "\033[0m")
            exit()
        

if __name__ == '__main__':
    main()
