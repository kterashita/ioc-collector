import requests
import ipaddress
from tqdm import tqdm


def enrich_ip(ip, config_dict):
    """
    expected input:
        str(ip):
            - resolve target,
            - ip address,
            - str
            - if ip is not ipaddress, ignore it
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

    """ old sample
    batch_list_enrich = batch_list
    for batch in batch_list:  # needs to be tqdm-ed, instad of vt()
        try:
            ip = ipaddress.ip_address(batch)
            batch_list_enrich.extend(run_virustotal_ip_resolve(str(ip), config_dict))
        except:
            pass
    """

    # validate if it is ipaddress format
    try:
        api_ip = ipaddress.ip_address(api_ip)
         # call api
        headers = {
            'Accept': 'application/json',
            'x-apikey' : config_dict['virustotal']['apikey']
            }
        response = requests.get(
            api_url + str(api_ip) + api_limit,
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
    except:
        return ip
    
   


    