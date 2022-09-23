#!venv/bin/python3
import datetime
import signal
import socket
import sys
import threading
import time

import requests


class Config:
    questdb_socket_timeout = 10
    shelly_api_http_timeout = 10
    scrape_interval = 60
    backoff_strategy = [0.5, 1, 3, 3, 5, 60, 90]  # time in seconds


def main():
    if len(sys.argv) != 5:
        # questdb_address - ip_address:port (e.g. 192.168.130.10:9009)
        # device_id       - some id (e.g. dev0)
        # device_ip       - ip_address (e.g. 192.168.50.178)
        # device_type     - one of plug, plugs, ht
        print(f"Usage: {sys.argv[0]} <questdb_address> <device_id> <device_ip> <device_type>")
        return -1

    print(sys.argv)
    script_name, questdb_address, device_id, device_ip, device_type = sys.argv

    # questdb_address must be a tuple like ("192.168.130.10", 9009)
    questdb_address = questdb_address.split(":")
    questdb_address = (questdb_address[0], int(questdb_address[1]))

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
            # InfluxDB line protocol data
            data = ""

            print(datetime.datetime.now().astimezone().isoformat())

            # https://shelly-api-docs.shelly.cloud/gen1/#shelly-plug-plugs-status
            request = requests.get(f"http://{device_ip}/status", timeout=Config.shelly_api_http_timeout)
            request.raise_for_status()
            status = request.json()

            # print(json.dumps(status, separators=(',', ':')))

            timestamp = status["unixtime"]
            if timestamp == 0:
                timestamp = int(time.time())
            nano = "000000000"

            # https://shelly-api-docs.shelly.cloud/gen1/#shelly-plug-plugs-status
            if device_type in ("plug", "plugs"):
                for idx, meter in enumerate(status["meters"]):
                    data += f"shelly_plugs_meter1,device={device_id},idx={idx} " \
                            f"power={meter['power']}," \
                            f"overpower={meter['overpower']}," \
                            f"is_valid={meter['is_valid']}," \
                            f"counters_0={meter['counters'][0]}," \
                            f"counters_1={meter['counters'][1]}," \
                            f"counters_2={meter['counters'][2]}," \
                            f"total={meter['total']} " \
                            f"{timestamp}{nano}\n"

                # PlugS only
                if status.get("temperature", None) is not None:
                    data += f"shelly_plugs_temperature1,device={device_id} " \
                            f"overtemperature={status['overtemperature']}," \
                            f"tmp_tc={status['tmp']['tC']}," \
                            f"tmp_is_valid={status['tmp']['is_valid']} " \
                            f"{timestamp}{nano}\n"

            # https://shelly-api-docs.shelly.cloud/gen1/#shelly-h-amp-t-status
            if device_type == "ht":
                data += f"shelly_ht_meter1,device={device_id} " \
                        f"is_valid={status['is_valid']}," \
                        f"tmp_tc={status['tmp']['tC']}," \
                        f"tmp_tc_is_valid={status['tmp']['is_valid']}," \
                        f"hum_value={status['hum']['value']}," \
                        f"hum_is_valid={status['hum']['is_valid']}," \
                        f"bat_value={status['bat']['value']}," \
                        f"bat_voltage={status['bat']['voltage']}," \
                        f"connect_retries={status['connect_retries']}," \
                        f"sensor_error={status.get('sensor_error', 0)} " \
                        f"{timestamp}{nano}\n"

            print(data, end='')
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(Config.questdb_socket_timeout)
                sock.connect(questdb_address)
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

    return 0


if __name__ == "__main__":
    sys.exit(main())
