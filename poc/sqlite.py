#!/usr/bin/env python3

from datetime import datetime, timedelta
import argparse
import yaml
import sqlite3
import pandas as pd
import random


init_yaml_filename = "config.yaml.init"

def get_argparse():
    parser = argparse.ArgumentParser(
        description="Help text of this command."
    )
    parser.add_argument('-c', '--config', type=str, required=False,
                        help="yaml file")
    parser.add_argument('--sql', action='store_true', help="sql test")
    parser.add_argument('--sql_create', action='store_true', help="sql_create()")
    parser.add_argument('--sql_print', action='store_true', help="sql_print()")
    parser.add_argument('--sql_add', action='store_true', help="sql_add()")
    parser.add_argument('--sql_reported', action='store_true', help="sql_reported()")
    return parser.parse_args()


def load_config(args):
    with open(args.config, 'r') as f:
        config_yaml = yaml.safe_load(f)
        #
        # PyYAML yaml.load(input) Deprecation
        # https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
        #
        # print(config_yaml['urlscanio']['apikey'])
    return config_yaml


def sql_test(config_dict):
    print("\033[34m# Run: sql_test()" + "\033[0m")
    db_name = 'urlscan.db'
    table_name = 'scan_result'
    conn = sqlite3.connect(db_name)
    conn_cur = conn.cursor()

    id_random = random.randrange(999)
    conn_cur.execute(f"insert into {table_name} values({id_random}, 'line')")
    conn.commit()
    
    # query = 'create table scan_result(uuid integer, brand text);'
    """ show db as list
    query = f'select * from {table_name}'
    table = conn_cur.execute(query)
    data = table.fetchall()
    print(data)
    """

    df = pd.read_sql(f'SELECT * FROM {table_name}', conn)
    print(df)
    
    conn_cur.close()
    conn.close()


def sql_create(config_dict):
    # print func header
    print("\033[34m# Run: sql_create()" + "\033[0m")

    # setup db
    db_name = config_dict['sqlite']['db_name']
    table_name = config_dict['sqlite']['table_name']

    # connect db
    conn = sqlite3.connect(db_name)
    conn_cur = conn.cursor()

    # create db
    query = f'''create table {table_name}(
        uuid text PRIMARY KEY,
        brand text,
        task_time text,
        url,
        ips,
        report_jpcert numeric,
        report_fortiguard numeric
        );'''
    conn_cur.execute(query)
    conn.commit()

    # close db
    conn_cur.close()
    conn.close()


def sql_print(config_dict):
    # print func header
    print("\033[34m# Run: sql_print()" + "\033[0m")

    # setup
    db_name = config_dict['sqlite']['db_name']
    table_name = config_dict['sqlite']['table_name']
    conn = sqlite3.connect(db_name)
    conn_cur = conn.cursor()

    # print db
    df = pd.read_sql(f'SELECT * FROM {table_name}', conn)
    print(df)

    # close db
    conn_cur.close()
    conn.close()


def sql_add(values_dict_list, config_dict):
    """ excepted format of values_dict_list
    # multiple entry
    [
        {
            'uuid': "",
            'brand': [""],  # " ".join(list)
            'task_time': ""
        },
        {
            'uuid': "",
            'brand': [""],  # " ".join(list)
            'task_time': ""
        }
    ]
    """
    # print func header
    print("\033[34m# Run: sql_add()" + "\033[0m")

    # setup db
    db_name = config_dict['sqlite']['db_name']
    table_name = config_dict['sqlite']['table_name']
    conn = sqlite3.connect(db_name)
    conn_cur = conn.cursor()

    # query add loop
    for dict in values_dict_list:
        value_uuid = dict['uuid']
        value_brand = dict['brand']
        value_task_time = dict['task_time']
        conn_cur.execute(f'''INSERT INTO {table_name} values(
            '{value_uuid}',
            '{value_brand}',
            '{value_task_time}',
            0,
            0
            )''')
    conn.commit()

    # close db
    conn_cur.close()
    conn.close()


#def sql_reported(uuid, report_jpcert, report_fortiguard, config_dict):
def sql_reported(config_dict):  # for test without values_dict
    # print func header
    print("\033[34m# Run: sql_add()" + "\033[0m")

    # testing input
    uuid = '65905527-c843-4daf-bd5a-d80f0bebb134'
    reported_jpcert = 1
    reported_fortiguard = 0

    # setup db
    db_name = config_dict['sqlite']['db_name']
    table_name = config_dict['sqlite']['table_name']
    conn = sqlite3.connect(db_name)
    conn_cur = conn.cursor()

    # query
    query = f'''UPDATE {table_name} SET
        report_jpcert = {reported_jpcert}
        WHERE uuid = '{uuid}'
    '''
    conn_cur.execute(query)
    conn.commit()

    # close db
    conn_cur.close()
    conn.close()


def main():
    args = get_argparse()
    
    if args.config:
        config_dict = load_config(args)
    if args.sql_create:
        sql_create(config_dict)
    if args.sql_print:
        sql_print(config_dict)
    if args.sql_add:
        sql_add(config_dict)
    if args.sql_reported:
        sql_reported(config_dict)


if __name__ == '__main__':
    main()
