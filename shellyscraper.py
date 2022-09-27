#!venv/bin/python3
import http.server
import signal
import socket
import sys
import threading
import time
import urllib.parse

import requests


class Config:
    questdb_address = ("192.168.130.10", 9009)
    shellies = {
        # "device_id": "device_ip"
        "shellyplug-s-AAAAAA": "192.168.50.101",
        "shellyplug-s-BBBBBB": "192.168.50.102",
        "shellyht-CCCCCC": "192.168.50.103",
        "shellyht-DDDDDD": "192.168.50.104",
    }

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
            print(f"Program interrupted by the {signal_name}, graceful shutdown in progress.")
            sigterm_threading_event.set()
        else:
            print(f"Program interrupted by the {signal_name} again, forced shutdown in progress.")
            sys.exit(-1)

    for some_signal in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(some_signal, sigterm_handler)

    return sigterm_threading_event


def write_ilp_to_questdb(data):
    print(data, end='')

    # https://github.com/questdb/questdb.io/commit/35ca3c326ab0b3448ef9fdb39eb60f1bd45f8506
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(Config.questdb_socket_timeout_seconds)
        sock.connect(Config.questdb_address)
        sock.sendall(data.encode())
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()


def get_device_info(device_ip):
    # https://shelly-api-docs.shelly.cloud/gen1/#settings
    request = requests.get(f"http://{device_ip}/settings", timeout=Config.shelly_api_http_timeout_seconds)
    request.raise_for_status()
    settings = request.json()
    # print(json.dumps(settings, separators=(',', ':')))

    device_type = settings["device"]["type"]
    device_name = settings["name"]
    return device_type, device_name


def get_device_status_ilp(device_ip, device_type, device_name):
    # https://shelly-api-docs.shelly.cloud/gen1/#status
    request = requests.get(f"http://{device_ip}/status", timeout=Config.shelly_api_http_timeout_seconds)
    request.raise_for_status()
    status = request.json()
    # print(json.dumps(status, separators=(',', ':')))

    # https://shelly-api-docs.shelly.cloud/gen1/#shelly-plug-plugs-coiot
    if device_type in ("SHPLG2-1", "SHPLG-1", "SHPLG-S", "SHPLG-U1"):
        return shelly_plugs_status_to_ilp(device_name, status)

    # https://shelly-api-docs.shelly.cloud/gen1/#shelly-h-amp-t-coiot
    if device_type == "SHHT-1":
        return shelly_ht_status_to_ilp(device_name, status)


def shelly_plugs_status_to_ilp(device_name, status):
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


def shelly_ht_status_to_ilp(device_name, status):
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


def shelly_ht_report_to_ilp(device_id, temp, hum):
    # https://shelly-api-docs.shelly.cloud/gen1/#shelly-h-amp-t-settings-actions

    timestamp = int(time.time())
    nano = "000000000"

    # InfluxDB line protocol data
    data = f"shelly_ht_meter2,device_id={device_id} " \
           f"temp={temp}," \
           f"hum={hum} " \
           f"{timestamp}{nano}\n"

    return data


def device_status_loop(sigterm_threading_event, device_id, device_ip):
    backoff_idx = -1

    while True:
        try:
            device_type, device_name = get_device_info(device_ip)

            while True:
                data = get_device_status_ilp(device_ip, device_type, device_name)
                write_ilp_to_questdb(data)

                if sigterm_threading_event.wait(Config.scrape_interval_seconds):
                    break

                backoff_idx = -1

            if sigterm_threading_event.is_set():
                break

        except BaseException as e:
            print(str(e))
            backoff_idx = max(0, min(backoff_idx + 1, len(Config.backoff_strategy_seconds) - 1))
            backoff = Config.backoff_strategy_seconds[backoff_idx]
            if sigterm_threading_event.wait(backoff):
                break


class ShellyHtReportSensorValuesHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        device_id = qs.get("id", [None])[0]
        temp = qs.get("temp", [None])[0]
        hum = qs.get("hum", [None])[0]

        if device_id is not None \
                and temp is not None \
                and hum is not None:
            device_ip = Config.shellies.get(device_id, None)
            data = shelly_ht_report_to_ilp(device_id, temp, hum)

            try:
                if device_ip is not None:
                    # The http connection is still in progress. The H&T device definitely has active wifi.
                    device_type, device_name = get_device_info(device_ip)
                    data += get_device_status_ilp(device_ip, device_type, device_name)
            except BaseException as e:
                print(str(e))

            # This may already be happening after the connection is closed.
            questdb_thread = threading.Thread(target=write_ilp_to_questdb, args=(data,))
            questdb_thread.daemon = False
            questdb_thread.start()


def main():
    sigterm_threading_event = configure_sigterm_handler()

    for device_id, device_ip in Config.shellies.items():
        if device_id.startswith("shellyht"):
            continue
        status_thread = threading.Thread(target=device_status_loop,
                                         args=(sigterm_threading_event, device_id, device_ip,))
        status_thread.daemon = False
        status_thread.start()

    ht_report_webhook = http.server.HTTPServer(('0.0.0.0', 9080), ShellyHtReportSensorsValuesHandler)
    webhook_server_thread = threading.Thread(target=ht_report_webhook.serve_forever)
    webhook_server_thread.daemon = True
    webhook_server_thread.start()

    sigterm_threading_event.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
