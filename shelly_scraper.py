#!/usr/bin/env python3
import datetime
import signal
import socket
import sys
import threading
import time

import requests


class Config:
    questdb_address = ("192.168.130.10", 9009)
    questdb_socket_timeout = 10

    shellies = [("dev0", "192.168.50.178")]
    shelly_api_http_timeout = 10

    scrape_interval = 60
    backoff_strategy = [0.5, 1, 3, 3, 5, 60, 90]  # time in seconds


def main():
    sigterm_cnt = [0]
    sigterm_threading_event = threading.Event()

    def sigterm_handler(signal_number, current_stack_frame):
        signal_name = signal.Signals(signal_number).name

        sigterm_cnt[0] += 1
        if sigterm_cnt[0] == 1:
            print(f"Program interrupted by the {signal_name}, graceful shutdown in progress.")
            sigterm_threading_event.set()
        else:
            print(f"Program interrupted by the {signal_name} again, forced shutdown in progress.")
            sys.exit(-1)

    for some_signal in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(some_signal, sigterm_handler)

    backoff_idx = -1
    while True:
        try:
            for shelly in Config.shellies:
                device, ip = shelly

                print(datetime.datetime.now().astimezone().isoformat())

                # https://shelly-api-docs.shelly.cloud/gen1/#shelly-plug-plugs-status
                request = requests.get(f"http://{ip}/status", timeout=Config.shelly_api_http_timeout)
                request.raise_for_status()
                status = request.json()

                # print(json.dumps(status, separators=(',', ':')))

                # InfluxDB line protocol data
                data = ""

                timestamp = status["unixtime"]
                if timestamp == 0:
                    timestamp = int(time.time())
                nano = "000000000"

                for idx, meter in enumerate(status["meters"]):
                    total = meter["total"]
                    data += f"shelly_meter1,device={device},idx={idx} " \
                            f"power={meter['power']}," \
                            f"overpower={meter['overpower']}," \
                            f"is_valid={meter['is_valid']}," \
                            f"counters_0={meter['counters'][0]}," \
                            f"counters_1={meter['counters'][1]}," \
                            f"counters_2={meter['counters'][2]}," \
                            f"total={total} " \
                            f"{timestamp}{nano}\n"

                # PlugS only
                if status.get("temperature", None) is not None:
                    data += f"shelly_temperature1,device={device} " \
                            f"overtemperature={status['overtemperature']}," \
                            f"tc={status['tmp']['tC']}," \
                            f"is_valid={status['tmp']['is_valid']} " \
                            f"{timestamp}{nano}\n"

                print(data)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(Config.questdb_socket_timeout)
                    sock.connect(Config.questdb_address)
                    sock.sendall(data.encode())
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()

            if sigterm_threading_event.wait(Config.scrape_interval):
                break

            backoff_idx = -1

        except BaseException as e:
            print(str(e))
            backoff_idx = max(0, min(backoff_idx + 1, len(Config.backoff_strategy) - 1))
            backoff = Config.backoff_strategy[backoff_idx]
            if sigterm_threading_event.wait(backoff):
                break


if __name__ == "__main__":
    sys.exit(main())
