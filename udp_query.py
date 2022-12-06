
import datetime
import random

import pandas as pd
from dns import name, query, message, rdatatype, resolver


def google_dns(host,domain):
    try:


        #query_message = message.make_query(qname=domain, rdtype=rdatatype.A)

        query_message1 = message.make_query(qname=domain, rdtype=rdatatype.A)
        response_tcp1 = query.udp(query_message1, host, timeout=5)
        resolution_start = datetime.datetime.now()
        response_tcp = query.udp(query_message1, host, timeout=5)
        if response_tcp:
            resolution_end = datetime.datetime.now()
            time_taken = resolution_end - resolution_start
            time_taken_ms = (time_taken.microseconds / 1000)
            #time_google_dns.append(str(time_taken_ms))
        return time_taken_ms
        answer_bit=True
    except:
        print("No Resolution")
        answer_bit=False





if __name__ == '__main__':
    time_google_dns, time_google_dns_avg = [],[]
    df = pd.read_csv('quic_successful_11_28.csv')
    data_list = []
    answer_bit=True
    for i in range(len(df)):
        # print(df.iloc[i, 0], df.iloc[i, 1], df.iloc[i, 4])
        host = str(df.iloc[i, 0])
        #port = int(df.iloc[i, 1])

        time_taken_ms_dns=google_dns(host,"taobao.com")
        dict_data = {
            "resolver_ip": host,
            "resolution_time": time_taken_ms_dns,
            "status": [1]
        }
        if answer_bit:
            data_list.append(dict_data)
        df1 = pd.DataFrame(data_list)
    print(df1)
    print(len(df1))
    df1.to_csv("taobao_udp_"+str(random.randint(0,10))+".csv")


