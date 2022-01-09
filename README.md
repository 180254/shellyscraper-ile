# shellyplug-ilepradu

Scrape the data from Shelly Plug (S), insert them into QuestDB, and visualize the data in Grafana.

<img src="screenshot1.png" alt="screenshot1" width="1000" />

## stack

The solution consists of:

* Shelly Plug/Shelly Plug S (the device you must buy)
* QuestDB (database)
* Grafana (data visualization tool)
* scraper (a custom script that retrieves data using a device API and inserts them into the database)
* dashboard (data visualization dashboard)

## configuration

* Assign a fixed IP address to your Shelly Plug S device(s) on your router.
* Complete scraper.py script (somewhere at the beginning is the config section).
* Create a docker network and docker volumes for data storage.

```shell
docker network create --subnet=192.168.130.0/24 ilepradu
docker volume create ilepradu-questdb-data
docker volume create ilepradu-grafana-data
```

* Run everything that the solution consists of:

```shell
# https://questdb.io/docs/reference/configuration/#docker
docker run -d --restart=unless-stopped \
    --net ilepradu --ip 192.168.130.10 \
    --name=ilepradu-questdb \
    -p 9000:9000 -p 9009:9009 -p 8812:8812 -p 9003:9003 \
    -v ilepradu-questdb-data:/root/.questdb/ \
    questdb/questdb:6.1.3
```

```shell
# https://grafana.com/docs/grafana/latest/installation/docker/
docker run -d --restart=unless-stopped \
    --net ilepradu --ip 192.168.130.11 \
    --name=ilepradu-grafana \
    -p 3000:3000 \
    -v ilepradu-grafana-data:/var/lib/grafana \
    grafana/grafana-oss:8.3.3
```

```shell
docker build -t "ilepradu:0.0.1" -f Dockerfile .
docker run -d --restart=unless-stopped \
    --net ilepradu --ip 192.168.130.12 \
    --name=ilepradu-scraper \
    ilepradu:0.0.1
```

* Log in to grafana (admin:admin), add datasource (https://questdb.io/tutorial/2020/10/19/grafana/#create-a-data-source), and import
  dashboard (`shelly-dashboard.json`).
* Secure the solution (some passwords?, firewall rules?) if this is to be available outside your home network.

## other things worth mentioning

Perhaps you prefer the device to send data to the message broker instead of scraping data using an API.  
If so, check another solution: https://questdb.io/tutorial/2020/08/25/questitto/
