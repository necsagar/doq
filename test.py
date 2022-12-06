import pandas as pd

if __name__ == "__main__":
    dict_data = {
        "resolver_ip": "host",
        "port": "port",
        "handshake_time": "time_taken_ms_hs",
        "resolution_time": "time_taken_ms_dns",
        "status": [1]
    }

    if (2>1):
        df1 = pd.DataFrame(dict_data)
        df1=df1.append(other=df1,ignore_index=True)
        print(df1)



