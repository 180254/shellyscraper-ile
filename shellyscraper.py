#!venv/bin/python3
import http.server
import os
import signal
import socket
import sys
import threading
import time
import traceback
import typing
import urllib.parse

import requests


class Config:
    # ILE_QUESTDB_ADDRESS=ipv4host:port
    questdb_address = (
        os.environ.get("ILE_QUESTDB_ADDRESS").split(':', 1)[0],
        int(os.environ.get("ILE_QUESTDB_ADDRESS").split(':', 1)[1])
    )

    # gen1 plugs:
    #     Shelly Plug E SHPLG2-1
    #     Shelly Plug SHPLG-1
    #     Shelly Plug S SHPLG-S
    #     Shelly Plug US SHPLG-U1
    # ILE_SHELLY_GEN1_PLUGS=comma-separated list of IPs
    shelly_gen1_plug_devices_ips = list(filter(None, os.environ.get("ILE_SHELLY_GEN1_PLUGS", "").split(",")))

    questdb_socket_timeout_seconds = 10
    shelly_api_http_timeout_seconds = 10

    scrape_interval_seconds = 60
    backoff_strategy_seconds = [0.5, 1, 3, 3, 5, 60, 90]


def configure_sigterm_handler():
    sigterm_cnt = [0]
    sigterm_threading_event = threading.Event()

    def sigterm_handler(signal_number, current_stack_frame):
        signal_name = signal.Signals(signal_number).name

        sigterm_cnt[0] += 1
        if sigterm_cnt[0] == 1:
            print(f"Program interrupted by the {signal_name}, graceful shutdown in progress.", file=sys.stderr)
            sigterm_threading_event.set()
        else:
            print(f"Program interrupted by the {signal_name} again, forced shutdown in progress.", file=sys.stderr)
            sys.exit(-1)

    for some_signal in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(some_signal, sigterm_handler)

    return sigterm_threading_event


def print_exception(exception: BaseException) -> None:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    co_filename = exc_traceback.tb_frame.f_code.co_filename
    co_name = exc_traceback.tb_frame.f_code.co_name
    format_exception_only = traceback.format_exception_only(type(exception), exception)[0].strip()
    print(f"exception: {co_filename}:{exc_traceback.tb_lineno} ({co_name}) {format_exception_only}", file=sys.stderr)


# ilp = InfluxDB line protocol
# https://questdb.io/docs/reference/api/ilp/overview/
def write_ilp_to_questdb(data: str) -> None:
    print(data, end='')

    # https://github.com/questdb/questdb.io/commit/35ca3c326ab0b3448ef9fdb39eb60f1bd45f8506
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(Config.questdb_socket_timeout_seconds)
        sock.connect(Config.questdb_address)
        sock.sendall(data.encode())
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()


# Supported devices: all gen1 devices.
def get_gen1_device_type_and_name(device_ip: str) -> typing.Tuple[str, str]:
    # https://shelly-api-docs.shelly.cloud/gen1/#settings
    request = requests.get(f"http://{device_ip}/settings", timeout=Config.shelly_api_http_timeout_seconds)
    request.raise_for_status()
    settings = request.json()
    # print(json.dumps(settings, separators=(',', ':')), file=sys.stderr)

    device_type = settings["device"]["type"]
    device_name = settings["name"]
    return device_type, device_name


# Supported devices: gen1 plugs (SHPLG2-1, SHPLG-1, SHPLG-S, SHPLG-U1) and gen1 H&T (SHHT-1),
def get_gen1_device_status_ilp(device_ip: str, device_type: str, device_name: str) -> str:
    # https://shelly-api-docs.shelly.cloud/gen1/#status
    request = requests.get(f"http://{device_ip}/status", timeout=Config.shelly_api_http_timeout_seconds)
    request.raise_for_status()
    status = request.json()
    # print(json.dumps(status, separators=(',', ':')), file=sys.stderr)

    # https://shelly-api-docs.shelly.cloud/gen1/#shelly-plug-plugs-coiot
    if device_type in ("SHPLG2-1", "SHPLG-1", "SHPLG-S", "SHPLG-U1"):
        return shelly_gen1_plug_status_to_ilp(device_name, status)

    # https://shelly-api-docs.shelly.cloud/gen1/#shelly-h-amp-t-coiot
    if device_type == "SHHT-1":
        return shelly_gen1_ht_status_to_ilp(device_name, status)

    print(f"get_gen1_device_status_ilp: unsupported device_type: {device_type}", file=sys.stderr)
    return ""


#  Supported devices: gen1 plugs (SHPLG2-1, SHPLG-1, SHPLG-S, SHPLG-U1).
def shelly_gen1_plug_status_to_ilp(device_name: str, status) -> str:
    # https://shelly-api-docs.shelly.cloud/gen1/#shelly-plug-plugs-status

    timestamp = status["unixtime"]
    if timestamp == 0:
        timestamp = int(time.time())
    nano = "000000000"

    # InfluxDB line protocol data
    data = ""

    for idx, meter in enumerate(status["meters"]):
        data += f"shelly_plugs_meter1,device_name={device_name},idx={idx} " \
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
            data += f"shelly_plugs_temperature1,device_name={device_name} " \
                    f"overtemperature={status['overtemperature']}," \
                    f"tmp_tc={status['tmp']['tC']}," \
                    f"tmp_is_valid={status['tmp']['is_valid']} " \
                    f"{timestamp}{nano}\n"

    return data


# Supported devices: gen1 H&T (SHHT-1).
def shelly_gen1_ht_status_to_ilp(device_name: str, status: typing.Dict[str, typing.Any]) -> str:
    # https://shelly-api-docs.shelly.cloud/gen1/#shelly-h-amp-t-status

    timestamp = status["unixtime"]
    if timestamp == 0:
        timestamp = int(time.time())
    nano = "000000000"

    # InfluxDB line protocol data
    data = f"shelly_ht_meter1,device_name={device_name} " \
           f"is_valid={status['is_valid']}," \
           f"tmp_tc={status['tmp']['tC']}," \
           f"tmp_is_valid={status['tmp']['is_valid']}," \
           f"hum_value={status['hum']['value']}," \
           f"hum_is_valid={status['hum']['is_valid']}," \
           f"bat_value={status['bat']['value']}," \
           f"bat_voltage={status['bat']['voltage']}," \
           f"connect_retries={status['connect_retries']}," \
           f"sensor_error={status.get('sensor_error', 0)} " \
           f"{timestamp}{nano}\n"

    return data


def shelly_gen1_ht_report_to_ilp(device_id: str, temp: str, hum: str) -> str:
    # https://shelly-api-docs.shelly.cloud/gen1/#shelly-h-amp-t-settings-actions

    timestamp = int(time.time())
    nano = "000000000"

    # InfluxDB line protocol data
    data = f"shelly_ht_meter2,device_id={device_id} " \
           f"temp={temp}," \
           f"hum={hum} " \
           f"{timestamp}{nano}\n"

    return data


def gen1_plug_status_loop(sigterm_threading_event, device_ip):
    backoff_idx = -1

    while True:
        try:
            device_type, device_name = get_gen1_device_type_and_name(device_ip)

            while True:
                data = get_gen1_device_status_ilp(device_ip, device_type, device_name)
                write_ilp_to_questdb(data)

                if sigterm_threading_event.wait(Config.scrape_interval_seconds):
                    break

                backoff_idx = -1

            if sigterm_threading_event.is_set():
                break

        except BaseException as exception:
            print_exception(exception)
            backoff_idx = max(0, min(backoff_idx + 1, len(Config.backoff_strategy_seconds) - 1))
            backoff = Config.backoff_strategy_seconds[backoff_idx]
            if sigterm_threading_event.wait(backoff):
                break


class ShellyGen1HtReportSensorValuesHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

        query_string = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        device_id = query_string.get("id", [None])[0]
        temp = query_string.get("temp", [None])[0]
        hum = query_string.get("hum", [None])[0]

        if device_id is not None \
                and temp is not None \
                and hum is not None:
            data = shelly_gen1_ht_report_to_ilp(device_id, temp, hum)

            try:
                device_ip = self.client_address[0]
                # The http connection is still in progress. The H&T device definitely has active Wi-Fi.
                device_type, device_name = get_gen1_device_type_and_name(device_ip)
                data += get_gen1_device_status_ilp(device_ip, device_type, device_name)
            except BaseException as exception:
                print_exception(exception)

            # This may already be happening after the connection is closed.
            questdb_thread = threading.Thread(target=write_ilp_to_questdb, args=(data,))
            questdb_thread.daemon = False
            questdb_thread.start()


def main():
    print("Config" + str(vars(Config)), file=sys.stderr)

    sigterm_threading_event = configure_sigterm_handler()

    for device_ip in Config.shelly_gen1_plug_devices_ips:
        status_thread = threading.Thread(target=gen1_plug_status_loop, args=(sigterm_threading_event, device_ip,))
        status_thread.daemon = False
        status_thread.start()

    # Handle Shelly H&T's action: "report sensor values".
    shelly_ht_report_webhook = http.server.HTTPServer(('0.0.0.0', 9080), ShellyGen1HtReportSensorValuesHandler)
    webhook_server_thread = threading.Thread(target=shelly_ht_report_webhook.serve_forever)
    webhook_server_thread.daemon = True
    webhook_server_thread.start()

    sigterm_threading_event.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
