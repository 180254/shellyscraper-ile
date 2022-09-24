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

* Assign a fixed IP address to your Shelly device(s) on your router.
* Complete the `shellyscraper.py` script (somewhere at the beginning is the config section).
* Create a docker network and docker volumes for data storage.

```shell
docker network create --subnet=192.168.130.0/24 ile
docker volume create ile-questdb-data
docker volume create ile-grafana-data
```

* Run everything that the solution consists of:

```shell
# https://questdb.io/docs/reference/configuration/#docker
docker run -d --restart=unless-stopped \
    --net ile --ip 192.168.130.10 \
    --name=ile-questdb \
    -p 9000:9000 -p 9009:9009 -p 8812:8812 -p 9003:9003 \
    -v ile-questdb-data:/root/.questdb/ \
    questdb/questdb:6.5.2
```

```shell
# https://grafana.com/docs/grafana/latest/installation/docker/
docker run -d --restart=unless-stopped \
    --net ile --ip 192.168.130.11 \
    --name=ile-grafana \
    -p 3000:3000 \
    -v ile-grafana-data:/var/lib/grafana \
    grafana/grafana-oss:8.5.13
```

```shell
docker build -t "sh-sc-ile:0.0.1" -f Dockerfile .
```

```shell
# questdb_address - questdb' ip_address:port (e.g. 192.168.130.10:9009)
# device_ip       - shelly' ip_address (e.g. 192.168.50.178)
docker run -d --restart=unless-stopped \
    --net ile \
    --name=ile-scraper-<device_ip> \
    sh-sc-ile:0.0.1 <questdb_address> <device_ip>
# e.g.
docker run -d --restart=unless-stopped \
    --net ile \
    --name=ile-scraper-192-168-50-178  \
    sh-sc-ile:0.0.1 192.168.130.10:9009 192.168.50.178 
```

* Log in to grafana (admin:admin), add datasource (https://questdb.io/tutorial/2020/10/19/grafana/#create-a-data-source), and import
  dashboard (`grafana-dashboard-shellyplugs1.json`).
* Secure the solution (some passwords?, firewall rules?) if this is to be available outside your home network.

## other things worth mentioning

Perhaps you prefer the device to send data to the message broker instead of scraping data using an API.  
If so, check another solution: https://questdb.io/tutorial/2020/08/25/questitto/
