#!venv/bin/python3
import asyncio
import datetime
import http.server
import json
import os
import re
import signal
import socket
import sys
import threading
import time
import traceback
import urllib.parse
from typing import Callable, List, Tuple

import requests
import websockets

"""
The script will scrape data from Shelly's devices and insert them into QuestDB.

Supported devices:
Name            | Model      | Table in QuestDB    | Scrape strategy
Shelly Plug     | SHPLG-1    | shelly_plugs_meter1 | API polling
Shelly Plug S   | SHPLG-S    | shelly_plugs_meter1 | API polling
Shelly Plug US  | SHPLG-U1   | shelly_plugs_meter1 | API polling
Shelly Plug E   | SHPLG2-1   | shelly_plugs_meter1 | API polling
Shelly H&T      | SHHT-1     | shelly_ht_meter1    | webhook (act as action URL)
Shelly Plus H&T | SNSN-0013A | shelly_ht_meter1    | receiving notifications (act as outbound WebSocket server)

Device configuration:
- Scape strategy: API polling
  Pass the IP address of the device using the ILE_SHELLY_IPS environment variable.
- Scape strategy: webhook
  Configure your devices so that the "report sensor values" URL is "http://{machine_ip}:9080/".
- Scape strategy: receiving notification
  Configure your devices so that the outgoing WebSocket server is "ws://{machine_ip}:9081/".
  
You can configure the script using environment variables.
Check the Env class below to determine what variables you can set.
"""


# --------------------- CONFIG ------------------------------------------------

class Env:
    # ILE_DEBUG=boolValueMaybeTrue
    ILE_DEBUG: str = os.environ.get("ILE_DEBUG", "false")

    # ILE_QUESTDB_HOST=ipv4host
    # ILE_QUESTDB_PORT=intPort
    ILE_QUESTDB_HOST: str = os.environ.get("ILE_QUESTDB_HOST", "localhost")
    ILE_QUESTDB_PORT: str = os.environ.get("ILE_QUESTDB_PORT", "9009")

    # ILE_SHELLY_IPS=comma-separated list of IPs
    # List here the supported devices for which the script uses the 'API polling' strategy.
    ILE_SHELLY_IPS: str = os.environ.get("ILE_SHELLY_IPS", "")

    # ILE_SOCKET_TIMEOUT=intValue (seconds)
    # ILE_HTTP_TIMEOUT=intValue (seconds)
    ILE_SOCKET_TIMEOUT: str = os.environ.get("ILE_SOCKET_TIMEOUT", "10")
    ILE_HTTP_TIMEOUT: str = os.environ.get("ILE_HTTP_TIMEOUT", "10")

    # ILE_SCRAPE_INTERVAL=floatValue (seconds)
    # ILE_BACKOFF_STRATEGY=comma-separated list of floats (seconds)
    ILE_SCRAPE_INTERVAL: str = os.environ.get("ILE_SCRAPE_INTERVAL", "60")
    ILE_BACKOFF_STRATEGY: str = os.environ.get("ILE_BACKOFF_STRATEGY", "0.5,1,3,3,5,60,90")


class Config:
    debug: bool = Env.ILE_DEBUG.lower() == "true"
    questdb_address: Tuple[str, int] = (Env.ILE_QUESTDB_HOST, int(Env.ILE_QUESTDB_PORT))
    shelly_devices_ips: List[str] = list(filter(None, Env.ILE_SHELLY_IPS.split(",")))

    questdb_socket_timeout_seconds: int = int(Env.ILE_SOCKET_TIMEOUT)
    shelly_api_http_timeout_seconds: int = int(Env.ILE_HTTP_TIMEOUT)

    scrape_interval_seconds: int = int(Env.ILE_SCRAPE_INTERVAL)
    backoff_strategy_seconds: List[float] = list(map(float, filter(None, Env.ILE_BACKOFF_STRATEGY.split(","))))


# --------------------- HELPERS -----------------------------------------------

def print_(*args, **kwargs) -> None:
    timestamp = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    new_args = (timestamp,) + args
    print(*new_args, **kwargs)


def print_debug(msg_supplier: Callable[[], str]) -> None:
    if Config.debug:
        print_(msg_supplier())


def configure_sigterm_handler() -> threading.Event:
    sigterm_cnt = [0]
    sigterm_threading_event = threading.Event()

    def sigterm_handler(signal_number, current_stack_frame):
        signal_name = signal.Signals(signal_number).name

        sigterm_cnt[0] += 1
        if sigterm_cnt[0] == 1:
            print_(f"Program interrupted by the {signal_name}, graceful shutdown in progress.", file=sys.stderr)
            sigterm_threading_event.set()
        else:
            print_(f"Program interrupted by the {signal_name} again, forced shutdown in progress.", file=sys.stderr)
            sys.exit(-1)

    for some_signal in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(some_signal, sigterm_handler)

    return sigterm_threading_event


def json_dumps(data: dict) -> str:
    return json.dumps(data, separators=(',', ':'))


def print_exception(exception: BaseException) -> None:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    co_filename = exc_traceback.tb_frame.f_code.co_filename
    co_name = exc_traceback.tb_frame.f_code.co_name
    format_exception_only = traceback.format_exception_only(type(exception), exception)[0].strip()
    print_(f"exception: {co_filename}:{exc_traceback.tb_lineno} ({co_name}) {format_exception_only}", file=sys.stderr)


def http_call(device_ip: str, path_and_query: str) -> dict:
    request = requests.get(f"http://{device_ip}/{path_and_query}", timeout=Config.shelly_api_http_timeout_seconds)
    request.raise_for_status()
    data = request.json()
    print_debug(lambda: json_dumps(data))
    return data


# --------------------- QUESTDB -----------------------------------------------

# ilp = InfluxDB line protocol
# https://questdb.io/docs/reference/api/ilp/overview/
def write_ilp_to_questdb(data: str) -> None:
    if data is None or data == "":
        return

    # Fix ilp data.
    # Remove name=value pairs where value is None.
    if "None" in data:
        data = re.sub(r'[a-zA-Z0-9_]+=None,?', '', data).replace(' ,', ' ').replace(', ', ' ')

    print_(data, end='')

    # https://github.com/questdb/questdb.io/commit/35ca3c326ab0b3448ef9fdb39eb60f1bd45f8506
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(Config.questdb_socket_timeout_seconds)
        sock.connect(Config.questdb_address)
        sock.sendall(data.encode())
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()


# --------------------- SHELLY Gen1&Gen2 --------------------------------------

def shelly_get_device_gen_and_type(device_ip: str) -> Tuple[int, str]:
    # https://shelly-api-docs.shelly.cloud/gen1/#shelly
    # https://shelly-api-docs.shelly.cloud/gen2/ComponentsAndServices/Shelly/#http-endpoint-shelly
    shelly = http_call(device_ip, "shelly")

    # gen2
    if "gen" in shelly:
        device_gen = shelly["gen"]

        if device_gen == 2:
            device_type = shelly["model"]
        else:
            device_type = None

    # gen1
    else:
        device_gen = 1
        device_type = shelly["type"]

    return device_gen, device_type


# --------------------- SHELLY Gen1 -------------------------------------------

def shelly_get_gen1_device_info(device_ip: str) -> Tuple[str, str, str]:
    # https://shelly-api-docs.shelly.cloud/gen1/#settings
    settings = http_call(device_ip, "settings")

    device_type = settings["device"]["type"]
    device_id = settings["device"]["hostname"]
    device_name = settings["name"]

    return device_type, device_id, device_name


def shelly_get_gen1_device_status_ilp(device_ip: str, device_type: str, device_id: str, device_name: str) -> str:
    # https://shelly-api-docs.shelly.cloud/gen1/#shelly-plug-plugs-coiot
    if device_type in ("SHPLG2-1", "SHPLG-1", "SHPLG-S", "SHPLG-U1"):
        # https://shelly-api-docs.shelly.cloud/gen1/#status
        # https://shelly-api-docs.shelly.cloud/gen1/#shelly-plug-plugs-status
        status = http_call(device_ip, "status")
        return shelly_gen1_plug_status_to_ilp(device_id, device_name, status)

    # https://shelly-api-docs.shelly.cloud/gen1/#shelly-h-amp-t-coiot
    if device_type == "SHHT-1":
        # https://shelly-api-docs.shelly.cloud/gen1/#status
        # https://shelly-api-docs.shelly.cloud/gen1/#shelly-h-amp-t-status
        status = http_call(device_ip, "status")
        return shelly_gen1_ht_status_to_ilp(device_id, device_name, status)

    print_(f"The shelly_get_gen1_device_status_ilp failed for device_ip={device_ip} "
           f"due to unsupported device_type={device_type}.", file=sys.stderr)
    return ""


def shelly_gen1_plug_status_to_ilp(device_id: str, device_name: str, status: dict) -> str:
    # status = https://shelly-api-docs.shelly.cloud/gen1/#shelly-plug-plugs-status

    timestamp = status["unixtime"]
    if timestamp == 0:
        timestamp = int(time.time())
    nano = "000000000"

    # InfluxDB line protocol data
    data = ""

    for idx, meter in enumerate(status["meters"]):
        data += f"shelly_plugs_meter1,device_id={device_id},device_name={device_name},idx={idx} " \
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
            data += f"shelly_plugs_temperature1,device_id={device_id},device_name={device_name} " \
                    f"overtemperature={status['overtemperature']}," \
                    f"tmp_tc={status['tmp']['tC']}," \
                    f"tmp_is_valid={status['tmp']['is_valid']} " \
                    f"{timestamp}{nano}\n"

    return data


def shelly_gen1_ht_status_to_ilp(device_id: str, device_name: str, status: dict) -> str:
    # status = https://shelly-api-docs.shelly.cloud/gen1/#shelly-h-amp-t-status

    timestamp = status["unixtime"]
    if timestamp == 0:
        timestamp = int(time.time())
    nano = "000000000"

    # InfluxDB line protocol data
    data = f"shelly_ht_meter1,device_id={device_id},device_name={device_name} " \
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


# Handler for Shelly H&T's action "report sensor values".
# https://shelly-api-docs.shelly.cloud/gen1/#shelly-h-amp-t-settings-actions
class ShellyGen1HtReportSensorValuesHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

        device_ip = self.client_address[0]
        query_string = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        is_valid_ht_report = "id" in query_string and "temp" in query_string and "hum" in query_string
        print_debug(lambda: self.path)

        if is_valid_ht_report:
            device_id = query_string["id"][0]
            temp = query_string["temp"][0]
            hum = query_string["hum"][0]

            data = shelly_gen1_ht_report_to_ilp(device_id, temp, hum)

            try:
                # The http connection is still in progress. Device has active Wi-Fi.
                device_type, device_id, device_name = shelly_get_gen1_device_info(device_ip)
                data += shelly_get_gen1_device_status_ilp(device_ip, device_type, device_id, device_name)

            except BaseException as exception:
                print_exception(exception)

            # I/O operation that may be happening after the connection is closed.
            questdb_thread = threading.Thread(target=write_ilp_to_questdb, args=(data,))
            questdb_thread.daemon = False
            questdb_thread.start()

        else:
            print_(f"The ShellyGen1HtReportSensorValuesHandler failed for device_ip={device_ip} "
                   f"due to unsupported query: '{self.path}'.", file=sys.stderr)


# --------------------- SHELLY Gen2 -------------------------------------------

def shelly_get_gen2_device_name(device_ip: str) -> str:
    # https://shelly-api-docs.shelly.cloud/gen2/ComponentsAndServices/Sys#sysgetconfig
    sysconfig = http_call(device_ip, "rpc/Sys.GetConfig")
    device_name = sysconfig["device"]["name"]
    return device_name


def shelly_get_gen2_device_status_ilp(device_ip: str, device_type: str, device_name: str) -> str:
    print_(f"The shelly_get_gen2_device_status_ilp failed for device_ip={device_ip} "
           f"due to unsupported device_type={device_type}.", file=sys.stderr)
    return ""


def shelly_gen2_plusht_status_to_ilp(device_name: str, status: dict) -> str:
    # status = status in "NotifyFullStatus" notification format
    # https://shelly-api-docs.shelly.cloud/gen2/General/Notifications/#notifyfullstatus

    # Required components: 'src', sys, devicepower:0, temperature:0, humidity:0
    # https://shelly-api-docs.shelly.cloud/gen2/ComponentsAndServices/Sys/
    # https://shelly-api-docs.shelly.cloud/gen2/ComponentsAndServices/DevicePower/
    # https://shelly-api-docs.shelly.cloud/gen2/ComponentsAndServices/Temperature/
    # https://shelly-api-docs.shelly.cloud/gen2/ComponentsAndServices/Humidity/

    timestamp = int(status["params"]["ts"] or 0)
    if timestamp == 0:
        timestamp = int(time.time())
    nano = "000000000"

    device_id = status["src"]

    tmp_tc = status["params"]["temperature:0"]["tC"]
    tmp_is_valid = tmp_tc is not None and "errors" not in status["params"]["temperature:0"]
    hum_value = status["params"]["humidity:0"]["rh"]
    hum_is_valid = hum_value is not None and "errors" not in status["params"]["humidity:0"]
    is_valid = tmp_is_valid or hum_is_valid

    bat_value = status["params"]["devicepower:0"]["battery"]["percent"]
    bat_voltage = status["params"]["devicepower:0"]["battery"]["V"]

    # InfluxDB line protocol data
    data = f"shelly_ht_meter1,device_id={device_id},device_name={device_name} " \
           f"is_valid={is_valid}," \
           f"tmp_tc={tmp_tc}," \
           f"tmp_is_valid={tmp_is_valid}," \
           f"hum_value={hum_value}," \
           f"hum_is_valid={hum_is_valid}," \
           f"bat_value={bat_value}," \
           f"bat_voltage={bat_voltage}," \
           f"connect_retries=0," \
           f"sensor_error=0 " \
           f"{timestamp}{nano}\n"

    return data


async def shelly_gen2_outbound_websocket_handler(websocket: websockets.WebSocketServerProtocol, path: str) -> None:
    recv = await websocket.recv()
    payload = json.loads(recv)
    print_debug(lambda: json_dumps(payload))

    device_ip = websocket.remote_address[0]
    src = payload["src"]

    if src.startswith("shellyplusht-"):
        # "NotifyFullStatus" messages are valuable.
        # https://shelly-api-docs.shelly.cloud/gen2/General/Notifications/#notifyfullstatus
        # https://shelly-api-docs.shelly.cloud/gen2/General/SleepManagementForBatteryDevices
        if payload["method"] == "NotifyFullStatus":
            try:
                # The websocket connection is still in progress. Device has active Wi-Fi.
                device_name = shelly_get_gen2_device_name(device_ip)

            except BaseException as exception:
                print_exception(exception)
                device_name = None

            data = shelly_gen2_plusht_status_to_ilp(device_name, payload)

            # I/O operation that may be happening after the connection is closed.
            questdb_thread = threading.Thread(target=write_ilp_to_questdb, args=(data,))
            questdb_thread.daemon = False
            questdb_thread.start()

            # https://shelly-api-docs.shelly.cloud/gen2/General/SleepManagementForBatteryDevices
            await websocket.send("EndOfQueue")

    else:
        print_(f"The shelly_gen2_outbound_websocket_handler failed for device_ip={device_ip} "
               f"due to unsupported src={src}.", file=sys.stderr)


# --------------------- Main --------------------------------------------------

def shelly_device_status_loop(sigterm_threading_event, device_ip):
    backoff_idx = -1

    while True:
        try:
            device_gen, device_type = shelly_get_device_gen_and_type(device_ip)

            while True:
                if device_gen == 1:
                    device_type, device_id, device_name = shelly_get_gen1_device_info(device_ip)
                    data = shelly_get_gen1_device_status_ilp(device_ip, device_type, device_id, device_name)

                elif device_gen == 2:
                    device_name = shelly_get_gen2_device_name(device_ip)
                    data = shelly_get_gen2_device_status_ilp(device_ip, device_type, device_name)

                else:
                    data = ""
                    print_(f"The shelly_device_status_loop failed for device_ip={device_ip} "
                           f"due to unsupported device_gen={device_gen}.", file=sys.stderr)

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


def main():
    print_("Config" + str(vars(Config)), file=sys.stderr)

    sigterm_threading_event = configure_sigterm_handler()

    for device_ip in Config.shelly_devices_ips:
        status_thread = threading.Thread(target=shelly_device_status_loop, args=(sigterm_threading_event, device_ip,))
        status_thread.daemon = False
        status_thread.start()

    # Handle Shelly H&T's action: "report sensor values".
    shelly_ht_report_webhook = http.server.HTTPServer(('0.0.0.0', 9080), ShellyGen1HtReportSensorValuesHandler)
    webhook_server_thread = threading.Thread(target=shelly_ht_report_webhook.serve_forever)
    webhook_server_thread.daemon = True
    webhook_server_thread.start()

    # Act as WebSocket server. Handle gen2 notifications.
    # Let's mix classic http.server.HTTPServer with asyncio-based websockets!
    async def shelly_gen2_outbound_websocket_server():
        ws_server = await websockets.serve(shelly_gen2_outbound_websocket_handler, '0.0.0.0', 9081)
        await ws_server.server.serve_forever()

    # Horrible. Works and is compatible with sigterm_threading_event.
    websocket_sever_thread = threading.Thread(target=lambda: asyncio.run(shelly_gen2_outbound_websocket_server()))
    websocket_sever_thread.daemon = True
    websocket_sever_thread.start()

    print_("STARTED", file=sys.stderr)
    sigterm_threading_event.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
