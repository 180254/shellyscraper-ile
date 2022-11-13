# shellyscraper-ile

Scrape the data from Shelly Plug (S) and Shelly H&T, insert them into QuestDB, and visualize the data in Grafana.

<img src="screenshot1.png" alt="screenshot1" width="1000" />

## stack

The solution consists of:

* Shelly Plug/Shelly Plug S/Shelly H&T (the device you must buy)
* QuestDB (database)
* Grafana (data visualization tool)
* scraper (a custom script that retrieves data using a device API and inserts them into the database)
* dashboard (data visualization dashboard)

## configuration

* Assign a static IP address to your Shelly device(s) on your router.
* Complete the `shellyscraper.py` script (somewhere at the beginning is the config section).
* Create a docker network and docker volumes for data storage.

```shell
docker network create --subnet=192.168.130.0/24 ile-network
docker volume create ile-questdb-data
docker volume create ile-grafana-data
```

* Run everything that the solution consists of:

```shell
# https://questdb.io/docs/reference/configuration/#docker
docker run -d --restart=unless-stopped \
    --net ile-network --ip 192.168.130.10 \
    --name=ile-questdb \
    -p 9000:9000 -p 9009:9009 -p 8812:8812 -p 9003:9003 \
    -v ile-questdb-data:/root/.questdb/ \
    questdb/questdb:6.5.5
```

```shell
# https://grafana.com/docs/grafana/latest/installation/docker/
docker run -d --restart=unless-stopped \
    --net ile-network \
    --name=ile-grafana \
    -p 3000:3000 \
    -v ile-grafana-data:/var/lib/grafana \
    grafana/grafana-oss:8.5.15
```

```shell
docker build -t "ile-shellyscraper:0.0.1" -f Dockerfile .
```

As the value of the ILE_SHELLY_PLUGS env, enter the comma-separated list of IPs assigned to your Shelly Plug (S) devices.
```shell
docker run -d --restart=unless-stopped \
    --net ile-network \
    --name=ile-shellyscraper \
    -p 9080:9080 \
    -e ILE_QUESTDB_ADDRESS=192.168.130.10:9009 \
    -e ILE_SHELLY_PLUGS=192.168.50.101,192.168.50.102 \
    ile-shellyscraper:0.0.1
```

* Log in to grafana (admin:admin), add data source (https://questdb.io/tutorial/2020/10/19/grafana/#create-a-data-source), and import
  dashboards (`grafana-dashboard-shellyplugs1.json`, `grafana-dashboard-shellyht1.json`, `grafana-dashboard-shellyht2.json`).
* Configure your Shelly H&T devices so that the "report sensor values" url is "http://<docker_machine_ip>:9080".
* Secure the solution (some passwords? firewall rules?) if this is to be available outside your home network.

## other things worth mentioning

Perhaps you prefer the device to send data to the message broker instead of scraping data using an API.  
If so, check another solution: https://questdb.io/tutorial/2020/08/25/questitto/
