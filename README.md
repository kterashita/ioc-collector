# ioc_collector
- IOC Collector

# Tested version
- Python 3.8.9

# Architecture of this module

## default options

### initializing config

- this module uses local config yaml file by `-c` option
- this option provides config template as `config.yaml.init`
- sample: `./ioc_collector.py --init`
- this option ignore any other options
- this should be run by shell manyally to initialize your config

### loading config to this module

- `-c` option provides config date from local yaml file to this module
- this input is mandatory to run this module

## action options

- option `-a` is to specify action

### urlscan

- sample: `-a urlscan`
- to submit scanning jobs to urlscan.io from various sources by using ip/domain/url

## source options

- option `-s` is to specify source to be sent by `-a` option

### twitter

## option combination

### `-a urlscan -s twitter`

- it kicks `urlscan_twitter()` function to call below process
1. run `twitter.search()`
  - input: search patterns defined in `config.yaml`
  - output: list, addressiable indicators (ip/domain/url)
2. run `virustotal.enrich_ip()`
  - input: str(indicator)
  - process: pickup only ip from input, resolving ptr records from virustotal passive database
  - output: list, append and extend into internal list variable to consolicate
  
