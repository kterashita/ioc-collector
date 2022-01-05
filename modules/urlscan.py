import requests
import json
import re
from tqdm import tqdm


def result(uuid, config_dict):
    """
    input:
      - str(uuid)
    run:
      - result api of urlscan
    output:
      - one dict which has brand result
    """
    
    """obsoluted to drop texting
    values_dict_list = []  # dict list to run sql_add()
    # result_dir_name = "urlscanio_results"
    """
    
    # setup api
    headers = {
        'API-Key': config_dict['urlscanio']['apikey'],
        'Content-Type': 'application/json'
        }
    api_url = "https://urlscan.io/api/v1/result/"

    # call api
    response = requests.get(
        api_url + str(uuid) + "/",
        headers=headers,
        )
    response_dict = response.json()

    """ obsoluted to drop texting
    if not os.path.exists(result_dir_name):
        os.makedirs(result_dir_name)
    
    # success_list = []  # to output only success result to stdout
    with open(result_dir_name + "/" + uuid + ".json", "w") as outfile:
        try:
            outfile.write(response_dict['page']['url'] + ": " + " ".join(response_dict['verdicts']['overall']['brands']))
            # success_list.append([response_dict['page']['url'], response_dict['verdicts']['overall']['brands'][0]])
            # Notify to MS Teams channel

            # make dict list to run sql_add()
            values_dict = {
                'uuid': uuid,
                'brand': " ".join(response_dict['verdicts']['overall']['brands']),
                'task_time': response_dict['task']['time'],
                'url': response_dict['page']['url'],
                'ips': " ".join(response_dict['lists']['ips'])
            }
            values_dict_list.append(values_dict)  # collecting dict list to pass to sql_add()
        except:
            pass
    # for success_result in success_list:
        # print(success_result[0], success_result[1])
    
    # remove if brand is empty
    if not response_dict['verdicts']['overall']['brands']:  # if 'brand' result is null
        os.remove(result_dir_name + "/" + uuid + ".json")  # remove the report local file
    """

    # to add results into .db
    # values_dict_list = []  # dict list to add sqlite
    try:
        if response_dict['verdicts']['overall']['brands']:  # if 'brand' result has brand result
            print('got brand result')
            values_dict = {
                'uuid': uuid,
                'brand': " ".join(response_dict['verdicts']['overall']['brands']),
                'task_time': response_dict['task']['time'],
                'url': response_dict['page']['url'],
                'ips': " ".join(response_dict['lists']['ips'])
            }
            # values_dict_list.append(values_dict)  # collecting dict list to pass to sql_add()
            # sql_add(values_dict_list, config_dict)
        else:
            print('got no brand')
            values_dict = None
    except:
        values_dict = None

    return values_dict  # has brand result


def publicscan(ioc_list, config_dict):
    """
    input:
      - list of ioc
    run:
      - submit public scan through urlscan.io api
    output
      - list of succeeded uuid
    """

    # setup api
    headers = {
        'API-Key': config_dict['urlscanio']['apikey'],
        'Content-Type': 'application/json'
        }
    api_url = "https://urlscan.io/api/v1/scan/"

    # Indicator
    message = f'# Run: urlscan.publicscan() for {str(len(ioc_list))}.'
    print("\033[34m" + message + "\033[0m")

    uuid_list = []
    exclude_patterns = [
        '\.mercari\.com\/*$',
        '\.virustotal\.com\/*$'
    ]
    for i in tqdm(range(len(ioc_list))):
        # exclution to skip scanning valid domain first. but it does not affect 'Effective' redirected url
        if re.search('|'.join(exclude_patterns), ioc_list[i]):
            print(ioc_list[i])
            continue
        data = {
            "url": ioc_list[i],
            "visibility": "public"
            }
        response = requests.post(
            api_url,
            headers=headers,
            data=json.dumps(data)
            )
        try:
            # verify the request was success without error
            uuid_list.append(response.json()['uuid'])
        except:
            # if the request got error, do nothing
            pass

    """ before
    this function had been called as like this

    for i in tqdm(range(len(uuid_list)), desc='writing uuid'):
        run_urlscanio_result(uuid_list[i], config_dict)  # output result

    """

    return uuid_list


