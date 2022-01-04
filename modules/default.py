import yaml

init_yaml_filename = 'config.yaml.init'

def init_config():
    config = {
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
        },
        'sqlite': {
            'db_name': "",
            'table_name': ""
        }
    }
    message = f'Saved initial yaml config file: {init_yaml_filename}'
    print("\033[34m" + message + "\033[0m")

    with open(init_yaml_filename, 'w') as f:
        yaml.dump(config, f)


def load_config(args):
    try:
        with open(args.config, 'r') as f:
            config_yaml = yaml.safe_load(f)
            #
            # PyYAML yaml.load(input) Deprecation
            # https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
            #
            # sample: print(config_yaml['urlscanio']['apikey'])
    except:
        message = f'Please specify a valid config file: {args.config}'
        print("\033[31m" + message + "\033[0m")
        exit()
    
    
    return config_yaml