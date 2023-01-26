import glob
import os
import random
import re
import requests
import subprocess
import sys
import time
import urllib

import scrapy
from scrapy.spiders import Spider
from scrapy.spidermiddlewares.httperror import HttpError
from scrapy.http import Request
from scrapy.linkextractors import LinkExtractor
import selenium
from termcolor import colored, cprint


# JavaScript events that should be attempted to be triggered via Selenium
JS_EVENTS = ["onerror", "onchange", "onsearch", "onsubmit", "onkeypress", "onkeyup", "onkeydown",
          "onclick", "onmouseover", "onwheel", "onmousedown", "onmouseup", "ondrop", "onended",
          "onplay", "onpause", "ontoggle"]
SELENIUM_HEADERS = []


class ArachneSpider(Spider):
    name = "arachne_spider"
    custom_settings = {
        'LOG_ENABLED': False,
        # 'LOG_LEVEL': 'INFO',
        'RETRY_ENABLED': False
    }

    def __init__(self, base_url, config, **kwargs):
        super().__init__(**kwargs)
        
        self.base_url = base_url
        self.verbose = True
        self.config = config
        self.found_urls = set()
        self.retry_urls = {}
        self.crawled_urls = {}
        self.crawled_paths = {}
        self.param_infos = {}
        self.found_cookies = []
        self.redirects = {}
        self.driver = None
        self.exclude_paths = []
        self.restrict_paths = config['restrict_paths']
        
        # figure out domain
        parsed_url = urllib.parse.urlparse(base_url)
        self.domain = parsed_url.hostname
        self.port = parsed_url.port
        if not self.port:
            self.port = 80 if parsed_url.scheme == "http" else 443
        self.protocol_prefix = "%s://" % parsed_url.scheme

        # compile exclude path regexes from config
        self.exclude_paths = []
        for exclude_path in self.config.get("exclude_paths", []):
            self.exclude_paths.append(re.compile(exclude_path))

        # parse headers from config
        self.cookies, self.headers = {}, {}
        for header in self.config["headers"]:
            if ':' not in header:
                continue

            key, val = header.split(':', maxsplit=1)
            key, val = key.strip(), val.strip()
            if key.lower() == 'cookie':
                for cookie in val.split(';'):
                    if "=" not in cookie:
                        self.cookies[cookie.strip()] = ''
                    else:
                        ckey, cval = cookie.split('=')
                        self.cookies[ckey.strip()] = cval.strip()

        # setup selenium if it is configured to be used
        if config["use_selenium"]:
            import logging
            logging.getLogger("seleniumwire").setLevel(logging.ERROR)
            from seleniumwire import webdriver
            from selenium.webdriver.chrome.options import Options
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--user-agent=%s' % self.config['user_agent'])

            # on Linux running Selenium as root requires '--no-sandbox' option
            if os.geteuid() == 0 and sys.platform.startswith('linux'):
                chrome_options.add_argument('--no-sandbox')
                # chrome_options.add_argument('--disable-dev-shm-usage')
            self.driver = webdriver.Chrome(options=chrome_options)

            # disallow downloads via Selenium (see https://stackoverflow.com/a/47366981)
            self.driver.command_executor._commands['send_command'] = ('POST', '/session/$sessionId/chromium/send_command')
            params = {'cmd': 'Page.setDownloadBehavior', 'params': {'behavior': 'disallow', 'downloadPath': ''}}
            self.driver.execute('send_command', params)

            # add cookies
            self.driver.get(self.base_url)  # initial request required to add cookies
            self.driver.delete_all_cookies()
            for key, val in self.cookies.items():
                self.driver.add_cookie({'name': key, 'value': val, 'domain': self.domain})

            # set up setting of headers
            global SELENIUM_HEADERS
            SELENIUM_HEADERS = self.config['headers']

    def __del__(self):
        """
        Delete this crawler object and properly free the used resources.
        """

        # quit selenium driver
        if self.driver:
            self.driver.quit()

        # make sure to delete linkfinder temporary files
        files = glob.glob("linkfinder_tmp*")
        for file in files:
            os.remove(file)

    def start_requests(self):
        """Set up initial requests"""

        for url in self.start_urls:
            req = Request(url, callback=self.parse, dont_filter=True, errback=self.on_error,
                          meta={'dont_redirect': True, 'handle_httpstatus_list': [301, 302, 401, 403, 404, 405]})
            yield req

    def parse(self, response):
        """Parse the provided response"""

        if response.status == 404:
            yield None

        # store response HTTP code if not redirect
        if not (response.status == 301 or response.status == 302):
            if response.url not in self.crawled_urls:
                self.crawled_urls[response.url] = response.status

        # some colorful printing
        if self.verbose:
            code = str(response.status)
            extra_print = ''
            if code[0] == '2':
                color = 'green'
            elif code[0] == '3':
                color = 'cyan'
                extra_print = colored(" --> ", 'cyan') + response.headers["Location"].decode()
            elif code[0] == '4':
                color = 'red'
            elif code[0] == '5':
                color = 'magenta'
            else:
                color = ''
            print_str = ' [' + colored(str(response.status), color) + '] ' + response.url + extra_print
            print(print_str)

        # extract cookies and their paths from HTTP response header
        cookie_paths = extract_cookies(response.headers.getlist("Set-Cookie"), response.url)
        cookie_urls = set()
        for path in cookie_paths:
            cookie_urls.add(self.to_absolute_url(path, response.urljoin))


        # use scrapy's lxml linkextractor to extract links / URLs
        scrapy_urls = set()
        try:
            ## TODO: use some other extractor for JSON and XML
            if 'html' in response.headers.get('Content-Type', b'').decode() or 'txt' in response.headers.get('Content-Type', b'').decode():
                # extract <base> URL's domain if a <base> tag exists
                base_domain = ""
                base_tag_sels = response.xpath("//base")

                for base_tag_sel in base_tag_sels:
                    href_sels = base_tag_sel.xpath("@href")
                    if href_sels:
                        href = href_sels.extract_first()
                        base_domain = urllib.parse.urlparse(href).netloc
                        break

                # setup allowed domains and extract new links
                allowed_domains = [self.domain, "%s:%s" % (self.domain, self.port)]
                if base_domain:
                    allowed_domains.append(base_domain)

                raw_scrapy_links = LinkExtractor(allow_domains=allowed_domains,
                                            tags=("a", "area", "script", "link", "source", "img"),
                                            attrs=("src", "href"),
                                            deny_extensions=set()).extract_links(response)
                raw_scrapy_urls = [link.url for link in raw_scrapy_links]

                # copy discovered URLs and additionally insert initial network location
                scrapy_urls = raw_scrapy_urls.copy()
                if base_domain and base_domain != allowed_domains[0] and base_domain != allowed_domains[1]:
                    orig_netloc = urllib.parse.urlparse(response.url).netloc
                    for scrapy_url in raw_scrapy_urls:
                        parsed_scrapy_url = list(urllib.parse.urlsplit(scrapy_url))
                        parsed_scrapy_url[1] = orig_netloc
                        scrapy_urls.append(urllib.parse.urlunsplit(parsed_scrapy_url))
                scrapy_urls = set(scrapy_urls)
        except (AttributeError, scrapy.exceptions.NotSupported) as e:
            if str(e) == "Response content isn't text":
                # stop processing and return no new URLs
                return set()
            raise e


        # run the different URL / link discovery mechanisms
        linkfinder_urls, dynamic_urls, form_urls, sub_urls = set(), set(), set(), set()
        if self.config['use_linkfinder']:
            try:
                linkfinder_urls = self.run_linkfinder(response.text, response.urljoin)
            except (AttributeError, scrapy.exceptions.NotSupported):
                pass
                
        if self.config['use_selenium']:
            dynamic_urls = self.extract_dynamic_urls(response.url)
        if self.config['extract_info_from_forms']:
            form_data = extract_form_data(response)
            # extract new URLs and HTTP parameters from parsed form data
            form_urls = self.process_form_data(form_data, response.urljoin)

        # extract URLs for parent paths
        sub_urls = extract_parent_urls(response.url)

        # unite discovered URLs
        urls = set()
        urls |= cookie_urls
        urls |= scrapy_urls
        urls |= linkfinder_urls
        urls |= dynamic_urls
        urls |= form_urls
        urls |= sub_urls

        # store info about redirect and add redirect URL to discovered URLs
        if response.status == 301 or response.status == 302:
            location = response.headers["Location"].decode()
            self.redirects[response.url] = {"code": response.status, "to": location}
            urls.add(self.to_absolute_url(location, response.urljoin))

        # process all the discovered URLs, i.e. extract new information and decide which to crawl
        yield_urls = set()
        for url in urls:
            # strip anchor
            if "#" in url:
                url = url[:url.rfind("#")]

            # replace entities and parse URL
            url = url.replace("&amp;", "&")
            url = url.replace("&#038;", "&")
            parsed_url = urllib.parse.urlparse(url)

            # disregard information about directory listing sorting
            if parsed_url.path.endswith("/") and re.match("C=[A-Z];O=[A-Z]", parsed_url.query):
                continue

            # extract GET parameters and cut URL if option is configured
            params = {}
            if parsed_url.query:
                if not self.config['crawl_parameter_links']:
                    url = "%s://%s/%s" % (parsed_url.scheme, parsed_url.netloc, parsed_url.path)
                params = get_query_params(parsed_url.query)
            elif url.endswith("?"):
                url = url[:-1]

            # add URL as instance of its path
            if self.url_has_netloc(url) and self.url_has_base_path(url) and params:
                self.add_path_instance(parsed_url.path, params, {}, {})

            # skip already discovered URLs
            if url in self.found_urls:
                continue
            self.found_urls.add(url)

            # skip URLs with different network location or path
            if not self.url_has_netloc(url):
                continue
            if not self.url_has_base_path(url):
                continue
            if url == response.url:
                continue

            # skip paths that are excluded from crawling
            if self.exclude_paths and url.count('/') > 2:
                check_str = '/' + '/'.join(url.split('/')[3:])
                if any(re_path.match(check_str) for re_path in self.exclude_paths):
                    print(' [ / ] ' + url)
                    continue

            # check whether to add this URL to the to-be-crawled URLs
            if url not in yield_urls:
                # limit the crawling depth
                max_depth = self.config['max_depth']
                if max_depth > 0:
                    depth = parsed_url.path.count("/")
                    if depth > max_depth:
                        continue

                # limit the number of times a path can be crawled to avoid endless
                # crawling upon GET parameter variation
                if parsed_url.path not in self.crawled_paths:
                    self.crawled_paths[parsed_url.path] = 0
                self.crawled_paths[parsed_url.path] += 1
                if self.crawled_paths[parsed_url.path] > self.config['max_path_visits']:
                    continue

                yield_urls.add(url)

        for url in yield_urls:
            req = Request(url, callback=self.parse, dont_filter=True, errback=self.on_error,
                          meta={'dont_redirect': True, 'handle_httpstatus_list': [301, 302, 401, 403, 404, 405]})
            yield req

    def on_error(self, failure):
        """Overrides the default method to catch and process e.g. status 500 responses"""

        if isinstance(failure.value, HttpError):
            if failure.request.url not in self.retry_urls:
                self.retry_urls[failure.request.url] = self.config['max_retries']

            self.retry_urls[failure.request.url] -= 1
            if self.retry_urls[failure.request.url] >= 0:
                req = Request(failure.request.url, callback=self.parse, dont_filter=True, errback=self.on_error,
                        meta={'dont_redirect': True, 'handle_httpstatus_list': [301, 302, 401, 403, 404, 405]})
                return req
            else:
                return self.parse(failure.value.response)

        if 'Connection refused' in str(failure.value):
            cprint('Connection refused: %s' % failure.request.url, 'red')

        return None

    def url_has_netloc(self, url):
        """
        Check if the given URL has the same network location as the base URL, i.e.
        if it has the same domain and port that are set in this crawler.
        """

        parsed_url = urllib.parse.urlparse(url)

        if parsed_url.scheme == "http":
            port = 80
        elif parsed_url.scheme == "https":
            port = 443
        if parsed_url.port:
            port = parsed_url.port

        domain = parsed_url.hostname
        if domain:
            if domain != self.domain or port != self.port:
                return False
            return True
        return False

    def url_has_base_path(self, url):
        """
        Check if the given URL's path is in scope, i.e. starts with a path that should be
        crawled. If no restricting paths were configured, True is returned for every given URL.
        """

        if not self.restrict_paths:
            return True
        else:
            parsed_url = urllib.parse.urlparse(url)
            for path in self.restrict_paths:
                if parsed_url.path.startswith(path):
                    return True
        return False

    def to_absolute_url(self, path_url, urljoin_fnct):
        """
        Convert the given path or url (param:path_url) to an absolute URL. If path_url starts
        with '/' it is an absolute server path and is joined with the configured network location
        of this crawler. Otherwise the path is relative and made absolute via the given URL join
        function. In the former case, port 80 and 443 are omitted in the returned absolute URL.
        """

        abs_url = path_url
        if not "://" in path_url:
            if path_url.startswith("/"):
                if self.port in (80, 443):
                    abs_url = urllib.parse.urljoin(self.protocol_prefix + self.domain, path_url)
                else:
                    abs_url = urllib.parse.urljoin(self.protocol_prefix + self.domain +
                                                   ":" + str(self.port), path_url)
            else:
                abs_url = urljoin_fnct(abs_url)
        return abs_url

    def add_path_instance(self, path, get_params: dict, body_params: dict, cookies: dict):
        """
        Add the instance of the given path, i.e. a request of the path with the given
        parameters to the list of instances for that path. If the parameter names within
        the given parameters are unknown, store them as well.
        """

        # disregard instances for sorting of directory listings
        if path.endswith("/") and set(get_params.keys()) == {"C", "O"}:
            return

        # first, store any unknown parameter names
        if get_params:
            self.add_parameters(path, "GET", set(get_params.keys()))
        if body_params:
            self.add_parameters(path, "POST", set(body_params.keys()))
        if cookies:
            self.add_parameters(path, "cookies", set(cookies.keys()))

        # next, check if instance should be stored and store it
        if path not in self.param_infos:
            self.param_infos[path] = {}

        if (not get_params) and (not body_params) and (not cookies):
            return

        if "instances" not in self.param_infos[path]:
            self.param_infos[path]["instances"] = []

        if not any(d.get("GET", {}) == get_params and d.get("POST", {}) == body_params and
                   d.get("cookies", {}) == cookies for d in self.param_infos[path]["instances"]):
            instance = {"GET": get_params, "POST": body_params, "cookies": cookies}
            self.param_infos[path]["instances"].append(instance)

    def add_parameters(self, path, method, params: set):
        """
        Store the given HTTP parameters alongside their path and HTTP method.
        """
        if path not in self.param_infos:
            self.param_infos[path] = {}

        method = method.upper()
        if method not in self.param_infos[path]:
            self.param_infos[path][method] = set()

        self.param_infos[path][method] |= params

    def extract_dynamic_urls(self, url):
        """
        Use Selenium to extract URLs that only become visible through requests made
        by executing a website's JavaScript code.
        """

        # delete previous requests and visit the given URL
        del self.driver.requests
        self.driver.get(url)

        # iterate over all JS event attributes
        for event_attribute in JS_EVENTS:
            # find all HTML elements with the current attribute
            try:
                elements = self.driver.find_elements('xpath', '//*[@%s]' % event_attribute)
            except Exception as e:
                if 'unexpected alert open:' in str(e):
                    continue
                raise e

            # run the JavaScript of every eventful HTML element
            if elements:
                print(elements)
                for element in elements:
                    # try submit and click events directly and other attributes via a workaround
                    try:
                        if event_attribute == 'onsubmit':
                            element.submit()
                        elif event_attribute == 'onclick':
                            element.click()
                        else:
                            self.driver.execute_script('arguments[0].%s()' % event_attribute, element)
                    # except any errors and ignore them
                    except:
                        pass

                    # go back to the original URL by going back in history
                    # if that fails, try to revisit the original URL directly
                    i = -1
                    while True:
                        try:
                            if self.driver.current_url != url:
                                break
                            else:
                                self.driver.execute_script('window.history.go(%d)' % i)
                                i -= 1
                        except selenium.common.exceptions.UnexpectedAlertPresentException as e:
                            for j in range(5):
                                try:
                                    self.driver.get(url)
                                    break
                                except selenium.common.exceptions.UnexpectedAlertPresentException:
                                    time.sleep(j)

                    # if for some reason, the original URL could not be visited again, stop completely
                    if self.driver.current_url != url:
                        break

        # extract URLs, POST params and cookies by inspecting requests made by the Selenium driver
        visited_urls = set()
        for request in self.driver.requests:
            if 'url' in request.__dir__():
                req_url = request.url
            else:
                req_url = request.path

            # add as path instance if POST parameters are available
            if self.url_has_netloc(req_url) and self.url_has_base_path(req_url) and request.method == 'POST' and request.body:
                try:
                    body = request.body.decode()
                    post_params = get_query_params(body)
                    if post_params:
                        parsed_url = urllib.parse.urlparse(req_url)
                        get_params = get_query_params(parsed_url.query)
                        # extract cookies sent by the Selenium driver
                        cookie_strs = request.headers['Cookie'].split(';')
                        cookies = {}
                        for cookie_str in cookie_strs:
                            k, v = cookie_str.strip(), ''
                            if '=' in cookie_str:
                                k, v = cookie_str.strip().split('=')
                            cookies[k] = v
                        # finally, add as instance of the visited website path
                        self.add_path_instance(parsed_url.path, get_params, post_params, cookies)
                except:
                    pass
            visited_urls.add(req_url)

        del self.driver.requests
        return visited_urls

    def process_form_data(self, form_data, urljoin_fnct):
        """
        Process the given form data by extracting new URLs and GET / POST parameters.
        """

        urls = set()
        for form_data_entry in form_data:
            # make the action absolute and add it to the found URLs
            abs_action = self.to_absolute_url(form_data_entry["action"], urljoin_fnct)
            urls.add(abs_action)

            if not self.url_has_netloc(abs_action):
                continue
            if not self.url_has_base_path(abs_action):
                continue

            parsed_abs_action = urllib.parse.urlparse(abs_action)
            get_params = get_query_params(parsed_abs_action.query)
            post_params = {}

            # add the form's params to the GET / POST param info
            form_params = get_params if form_data_entry["method"] == "GET" else post_params
            for k, v in form_data_entry["params"].items():
                form_params[k] = v

            # check if the found path / parameter instance is new before appending it
            is_new_instance = True
            if parsed_abs_action.path in self.param_infos:
                if "instances" in self.param_infos[parsed_abs_action.path]:
                    for instance in self.param_infos[parsed_abs_action.path]["instances"]:
                        if (not get_params) or get_params == instance["GET"]:
                            post_keys = instance["POST"].keys()
                            if all(k in post_keys for k in post_params):
                                is_new_instance = False
            if is_new_instance:
                self.add_path_instance(parsed_abs_action.path, get_params, post_params, {})

        return urls

    def run_linkfinder(self, text, urljoin_fnct):
        """
        Use Linkfinder to discover new URLs in the given text. From experience, Linkfinder
        can produce a significant amount of false positives. The given url join function
        is used to constuct absolute URLs from discovered relative paths.
        """

        urls = set()
        # store the text in a separate file for Linkfinder
        tmp_filename_in = 'linkfinder_tmp_%d.in' % random.randint(0, 2**32)
        with open(tmp_filename_in, 'w') as f:
            f.write(text)

        # Run Linkfinder as subprocess and remove the input file thereafter
        linkfinder_out = ''
        try:
            linkfinder_out = subprocess.check_output(['python3 LinkFinder/linkfinder.py -i ' +
                                                      tmp_filename_in + ' -o cli 2>/dev/null'], shell=True)
            linkfinder_out = linkfinder_out.decode()
        except subprocess.CalledProcessError:
            pass
        os.remove(tmp_filename_in)

        # process Linkfinder's output
        for line in linkfinder_out.split("\n"):
            if not line:
                continue
            line = line.strip()
            line = self.to_absolute_url(line, urljoin_fnct)
            # if configured, check if the discovered URL is valid and exists
            if self.config['check_linkfinder']:
                try:
                    timeout = float(self.config['linkfinder_check_timeout'])
                    if self.url_has_netloc(line) and self.url_has_base_path(line) and line not in self.found_urls:
                        if str(requests.head(line, timeout=timeout).status_code) != '404':
                            urls.add(line)
                except:
                    pass
            else:
                urls.add(line)

        return urls


def get_query_params(query):
    """
    Extract (key, value) pairs from the given GET / POST query. Pairs
    can be split by '&' or ';'.
    """
    params = {}
    if query:
        delim = "&"
        if "&" not in query and ";" in query:
            delim = ";"
        for k_v in query.split(delim):
            k, v = k_v, ""
            if "=" in k_v:
                k, v = k_v.split("=")
            params[k] = v
    return params


def extract_parent_urls(url):
    """
    Extract parent URLs of the given URL.
    E.g. from http://example.org/a/b.php we get as parent URL http://example.org/a/
    """

    sub_urls = set()
    parsed_url = urllib.parse.urlparse(url)
    dirs = parsed_url.path.split("/")

    # strip empty dirs constructed from the above split
    if dirs and not dirs[0]:
        dirs = dirs[1:]
    if dirs and not dirs[-1]:
        dirs = dirs[:-1]

    for i in range(0, len(dirs)-1):
        sub_url = parsed_url.scheme + "://" + parsed_url.netloc + "/"
        sub_url += "/".join(dirs[:i+1]) + "/"
        sub_urls.add(sub_url)

    return sub_urls


def extract_form_data(response):
    """ Extract the HTML form information contained in the given response. """

    def add_param(element):
        """ Add the info of the given element to params if it has a name """
        nonlocal params
        name = element.attrib.get("name", None)
        value = element.attrib.get("value", "")
        if name:
            params[name] = value

    # find and iterate over all forms contained in the response
    form_data = []
    try:
        forms = response.xpath("//form")
    except (AttributeError, scrapy.exceptions.NotSupported):
        return []

    for form in forms:
        action = form.attrib.get("action", None)
        form_id = form.attrib.get("id", None)
        method = form.attrib.get("method", None)
        # only process forms with action and method attribute
        if (action is None) or (not method):
            continue
        # adjust action and method strings
        if action == "#" or action == "":
            action = response.url
        action = action.replace("&amp;", "&")
        action = action.replace("&#038;", "&")
        method = method.upper()

        # extract all the different parameters
        params = {}
        for _input in form.xpath("//input"):
            add_param(_input)

        for select in form.xpath("//select"):
            add_param(select)

        for textarea in form.xpath("//textarea"):
            add_param(textarea)

        # handle the use of form IDs
        if form_id:
            for _input in response.xpath("//input[@form='%s']" % form_id):
                add_param(_input)

            for select in response.xpath("//select[@form='%s']" % form_id):
                add_param(select)

            for textarea in response.xpath("//textarea[@form='%s']" % form_id):
                add_param(textarea)

        # if there is only one form, consider all inputs of the page to be part of this form
        if len(forms) == 1:
            for _input in response.xpath("//input"):
                add_param(_input)

            for select in response.xpath("//select"):
                add_param(select)

            for textarea in response.xpath("//textarea"):
                add_param(textarea)

        form_data.append({"action": action, "method": method, "params": params, "id": form_id})
    return form_data


def extract_cookies(cookie_headers, url):
    return []


def selenium_request_interceptor(request):
    for hkey, hval in SELENIUM_HEADERS:
        if hkey in request.headers:
            del request.headers[hkey]
        request.headers[hkey] = hval
