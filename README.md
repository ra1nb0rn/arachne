
# Arachne
*Arachne* is an in-depth crawler / spider for websites. WIP

## Installation
* For a simple installation, just run the ``install.sh`` script.
* If you want to install *Arachne* manually, make sure to have all Python packages installed as well as Selenium and LinkFinder if you want to use them.
* To build a Docker container, you can use the provided Dockerfile: ``docker container run -it -v "$(pwd):/home/arachne" --shm-size="1g" arachne:latest``

## Usage
* To simply crawl a website, you can run the following command:
```
./arachne.py -u https://example.org
```
* Other parameters can be viewed via the tool's help information:
```
root@294ee7598ef7:/home/arachne# ./arachne.py -h
usage: arachne.py [-h] -u URL [-c CONFIG] [-x PROXY] [-A USER_AGENT] [-H HEADER [HEADER ...]] [-p PATH [PATH ...]]
                  [-e EXCLUDE_PATH [EXCLUDE_PATH ...]] [-b COOKIE [COOKIE ...]] [-r RESTRICT_PATH [RESTRICT_PATH ...]]

Crawl endpoints of a web page.

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     The URL of the web page to crawl
  -c CONFIG, --config CONFIG
                        Config to use for crawling
  -x PROXY, --proxy PROXY
                        HTTP(S) proxy to send crawling traffic through
  -A USER_AGENT, --user-agent USER_AGENT
                        User Agent to use when crawling
  -H HEADER [HEADER ...], --header HEADER [HEADER ...]
                        Header to use when crawling
  -p PATH [PATH ...], --path PATH [PATH ...]
                        Additional path to crawl
  -e EXCLUDE_PATH [EXCLUDE_PATH ...], --exclude-path EXCLUDE_PATH [EXCLUDE_PATH ...]
                        Regex of path to exclude from crawling
  -b COOKIE [COOKIE ...], --cookie COOKIE [COOKIE ...]
                        Cookie string to use when crawling
  -r RESTRICT_PATH [RESTRICT_PATH ...], --restrict-path RESTRICT_PATH [RESTRICT_PATH ...]
                        Restrict crawling to path(s)
```

## License
*Arachne* is licensed under the MIT license, see [here](https://github.com/ra1nb0rn/arachne/blob/master/LICENSE).

