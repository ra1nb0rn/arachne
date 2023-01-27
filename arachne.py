#!/usr/bin/env python3

import argparse
import urllib.parse
import logging
import os
import json

from scrapy.crawler import CrawlerProcess

from crawl_spider import ArachneSpider

DEFAULT_CONFIG_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'default_config.json')

def load_config(user_config_file=None):
    """Load an parse config"""

    with open(DEFAULT_CONFIG_FILE) as f:
        config = json.load(f)

    if user_config_file:
        with open(user_config_file) as f:
            user_config = json.load(f)
        for key, val in user_config.items():
            config[key] = val

    return config


def banner():
    print("""
||   ||
 \\\\()//
//(__)\\\\
||    ||
    """
    )

def parse_args():
    parser = argparse.ArgumentParser(description='Crawl endpoints of a web page.')
    parser.add_argument('-u', '--url', type=str, help='The URL of the web page to crawl', required=True)
    parser.add_argument('-c', '--config', type=str, help='Config to use for crawling')
    parser.add_argument('-x', '--proxy', type=str, help='HTTP(S) proxy to send crawling traffic through')
    parser.add_argument('-A', '--user-agent', type=str, help='User Agent to use when crawling')
    parser.add_argument('-H', '--header', type=str, action='append', nargs='+', help='Header to use when crawling')
    parser.add_argument('-p', '--path', type=str, action='append', nargs='+', help='Additional path to crawl')
    parser.add_argument('-e', '--exclude-path', type=str, action='append', nargs='+', help='Regex of path to exclude from crawling')
    parser.add_argument('-b', '--cookie', type=str, action='append', nargs='+', help='Cookie string to use when crawling')
    parser.add_argument('-r', '--restrict-path', type=str, action='append', nargs='+', help='Restrict crawling to path(s)')

    return parser.parse_args()

def main():
    # load and parse default config
    config = load_config()
    
    # parse args
    args = parse_args()
    base_url = args.url
    config = load_config(args.config)
    start_urls = [base_url]

    if args.user_agent:
        config['user_agent'] = args.user_agent
    if args.header:
        headers = []
        for headers_iter in args.header:
            headers += headers_iter
        config['headers'] = headers
    if args.path:
        for paths in args.path:
            for path in paths:
                if path.startswith('/'):
                    path = path[1:]
                if base_url.endswith('/'):
                    start_urls.append(base_url + path)
                else:
                    start_urls.append(base_url + '/' + path)
    if args.exclude_path:
        exclude_paths = []
        for epaths in args.exclude_path:
            exclude_paths += epaths
        config['exclude_paths'] = exclude_paths
    if args.restrict_path:
        restrict_paths = []
        for rpaths in args.restrict_path:
            restrict_paths += rpaths
        config['restrict_paths'] = restrict_paths
    if args.cookie:
        cookies = []
        for cookies_iter in args.cookie:
            cookies += cookies_iter
        config['headers'].append('Cookie: ' + '; '.join(cookies))
    if args.proxy:
        config['proxy'] = args.proxy
    
    # set up scrapy / crawler and run it
    logging.getLogger("scrapy").propagate = False
    parsed_url = urllib.parse.urlparse(base_url)
    domain = parsed_url.hostname

    if config['proxy']:
        os.environ["http_proxy"] = config['proxy']
        os.environ["https_proxy"] = config['proxy']

    process = CrawlerProcess({
        'USER_AGENT': config['user_agent']
    })
    process.crawl(ArachneSpider, config=config, allowed_domains=[domain],
                  start_urls=start_urls, base_url=base_url)
    process.start()


if __name__ == "__main__":
    main()
