import argparse
import asyncio
import logging
import pickle
import ssl
import datetime
import struct
from typing import Optional, cast
import pandas as pd

from dnslib.dns import QTYPE, DNSHeader, DNSQuestion, DNSRecord
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicFileLogger

logger = logging.getLogger("client")


class DnsClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: Optional[asyncio.Future[DNSRecord]] = None

    async def query(self, query_name: str, query_type: str) -> None:
        # serialize query
        query = DNSRecord(
            header=DNSHeader(id=0),
            q=DNSQuestion(query_name, getattr(QTYPE, query_type)),
        )
        data = bytes(query.pack())
        data = struct.pack("!H", len(data)) + data

        # send query and wait for answer
        global resolution_start_dns
        resolution_start_dns = datetime.datetime.now()
        stream_id = self._quic.get_next_available_stream_id()
        self._quic.send_stream_data(stream_id, data, end_stream=True)
        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._ack_waiter is not None:
            if isinstance(event, StreamDataReceived):
                # parse answer
                global resolution_end_dns
                resolution_end_dns = datetime.datetime.now()
                length = struct.unpack("!H", bytes(event.data[:2]))[0]
                answer = DNSRecord.parse(event.data[2: 2 + length])

                # return answer
                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(answer)


def save_session_ticket(ticket):
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    # with open("session_ticket.txt", "w") as file:
    #     file.write(str(ticket))
    # if args.session_ticket:
    #     with open(args.session_ticket, "wb") as fp:
    #         pickle.dump(ticket, fp)


async def main(
        configuration: QuicConfiguration,
        host: str,
        port: int,
        query_name: str,
        query_type: str,
) -> None:
    global answer_bit
    logger.debug(f"Connecting to {host}:{port}")
    resolution_start_hs = datetime.datetime.now()
    try:
        async with connect(
                host,
                port,
                configuration=configuration,
                session_ticket_handler=save_session_ticket,
                create_protocol=DnsClientProtocol,
        ) as client:

            client = cast(DnsClientProtocol, client)
            #logger.debug("Sending DNS query")
            if (client):
                answer_bit=True

    except:
        print("Connection Problem")
        answer_bit=False


if __name__ == "__main__":
    df = pd.read_csv('totalscan.csv')
    data_list=[]
    verified_count=0
    for i in range(len(df)):
        # print(df.iloc[i, 0], df.iloc[i, 1])
        host = str(df.iloc[i, 0])
        #host="8.210.148.24"
        port = int(df.iloc[i, 1])
        #port=784
        print(f"################Test for Resolver: {host}##################")
        query_name = "google.com"
        query_type = "A"

        logging.basicConfig(
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
            level=logging.INFO,
        )

        configuration = QuicConfiguration(alpn_protocols=["doq-i02", "doq-i03", "doq-i00"], is_client=True)

        # configuration.verify_mode = ssl.CERT_NONE
        logger.debug("No session ticket defined...")
        # try:
        #     with open("session_ticket.txt", "rb") as fp:
        #         configuration.session_ticket = fp.read()
        # except FileNotFoundError:
        #     logger.debug(f"Unable to read ")
        #     pass
        asyncio.run(
            main(
                configuration=configuration,
                host=host,
                port=port,
                query_name=query_name,
                query_type=query_type,
            )
        )
        dict_data = {
            "resolver_ip": host,
            "port": port,
            "status": [1]
        }

        if (answer_bit):
            data_list.append(dict_data)
            verified_count+=verified_count
    df1 = pd.DataFrame(data_list)
    print(df1)
    print(len(df1))
    df1.to_csv("verifiedlist.csv")
    print(verified_count)


