import requests
import re


def test():
    print(1)


def search(args, config_dict):
    bearer = config_dict['twitter']['bearer']
    headers = {
        "Authorization": f"Bearer {bearer}"
    }
    url = "https://api.twitter.com/2/tweets/search/recent"
    
    # number of kerword parameter. ${params} dict is search keyword pattern
    params_len = len(config_dict['twitter']['keywords'])

    # initialize variants
    result = []
    results = []
    results_all = []

    # loop ${params_len} times, for each search keyword pattern
    for j in range(params_len):
        results = []
        params = {'query': config_dict['twitter']['keywords'][j]}
        r = requests.get(url, headers=headers, params=params)
        tweets = r.json()
        
        # sample
        # print(json.dumps(tweets, indent=4))

        # Indicator
        message = '# Twitter Keyword Pattern: ' + params['query']
        print("\033[34m" + message + "\033[0m")

        # sanitize
        for i in range(tweets['meta']['result_count']):
            result = []
            tweet = tweets['data'][i]['text']
            tweet = re.sub('IP:', ' ', tweet)
            tweet = re.sub('\[', '', tweet)
            tweet = re.sub('\]', '', tweet)
            tweet = re.sub(';', ' ', tweet)
            tweet = re.sub('\(', ' ', tweet)
            tweet = re.sub('\)', ' ', tweet)
            for line in tweet.split():
                if re.search('\.', line):
                    # sanitize again at this point
                    line = re.sub('^\/', '', line)
                    # excluded word pattern 
                    if re.search('t.co|virustotal.com|…|%|^[0-9]*\.[0-9]+F*$|.{1,3}\..{0,1}$|🔥', line) is None:
                        result.append(line)
            # adding result per keyword
            results.extend(result)

        message = f'# Hit count before merge: {str(len(results))}'
        print("\033[34m" + message + "\033[0m")

        results_all.extend(results)

    return list(set(results_all))  # list