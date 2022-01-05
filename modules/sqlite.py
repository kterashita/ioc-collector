import os
import sqlite3
import pandas as pd


def initdb(config_dict):
    # setup db
    db_name = config_dict['sqlite']['db_name']
    table_name = config_dict['sqlite']['table_name']

    # if db file does not exist, create new
    conn = sqlite3.connect(db_name)
    conn_cur = conn.cursor()
    conn_cur.execute(f'''CREATE TABLE {table_name} (
        uuid text PRIMARY KEY,
        brand text,
        task_time text,
        url text,
        ips text,
        jpcert integer,
        fortiguard integer
        )''')
    conn.commit()

    # close db
    conn_cur.close()
    conn.close()


def print_all(args, config_dict):
    # setup
    db_name = config_dict['sqlite']['db_name']
    table_name = config_dict['sqlite']['table_name']
    conn = sqlite3.connect(db_name)
    conn_cur = conn.cursor()

    # indicator
    message = f'# Run: sqlite.print_all(): {db_name}.'
    print("\033[34m" + message + "\033[0m")

    # setup filter
    if args.source == 'all':
        column = '*'
    else:
        column = args.source

    # setup pandas
    pd.set_option('display.max_columns', 999)
    pd.set_option('display.max_rows', 999)

    # print db
    df = pd.read_sql(f'SELECT {column} FROM {table_name}', conn)
    print(df)

    # close db
    conn_cur.close()
    conn.close()


def add(values_dict, config_dict):
    """
    input:
      - dict including values with brand resuilt
    run:
      - writing into sqlite database
    output:
      - n/a
    """

    """ excepted format of values_dict
    {
        'uuid': "",
        'brand': [""],  # " ".join(list)
        'task_time': ""
        'url': ""
        'ips': ""
    }
    """
    # print func header
    # print("\033[34m# Run: sql_add()" + "\033[0m")

    # setup db
    db_name = config_dict['sqlite']['db_name']
    table_name = config_dict['sqlite']['table_name']

    # if db file does not exist, create new
    if not os.path.exists(db_name):
        message = f'# initialize db: {db_name}'
        print("\033[34m" + message + "\033[0m")
        initdb(config_dict)

    conn = sqlite3.connect(db_name)
    conn_cur = conn.cursor()

    """ obsoluted
    # query add loop
    for dict in values_dict_list:
        value_uuid = dict['uuid']
        value_brand = dict['brand']
        value_task_time = dict['task_time']
        value_url = dict['url']
        value_ips = dict['ips']
        conn_cur.execute(f'''INSERT INTO {table_name} values(
            '{value_uuid}',
            '{value_brand}',
            '{value_task_time}',
            '{value_url}',
            '{value_ips}',
            0,
            0
            )''')
    conn.commit()
    """

    # input variables
    value_uuid = values_dict['uuid']
    value_brand = values_dict['brand']
    value_task_time = values_dict['task_time']
    value_url = values_dict['url']
    value_ips = values_dict['ips']

    # write down to db
    conn_cur.execute(f'''INSERT INTO {table_name} values(
        '{value_uuid}',
        '{value_brand}',
        '{value_task_time}',
        '{value_url}',
        '{value_ips}',
        0,
        0
        )''')
    conn.commit()

    # close db
    conn_cur.close()
    conn.close()