# -*- coding: utf-8 -*-
#!/usr/bin/env python

"""
    ooooooooooooo
    8'   888   `8
         888      oooo d8b  .ooooo.  oooo    ooo oooo    ooo
         888      `888""8P d88' `88b  `88b..8P'   `88.  .8'
         888       888     888   888    Y888'      `88..8'
         888       888     888   888  .o8"'88b      `888'
        o888o     d888b    `Y8bod8P' o88'   888o     .8'
                                                 .o..P'
                                                 `Y8P'

    Awesome module for HTTP requests via Tor socks5 proxy
    ========================================================

    Features:
        DNS via Tor proxy
        GET, POST requests via Tor proxy
        GZIP support
        Identity change (IP, User-Agent, etc)
        Setting specific headers for different platforms

    Original idea by https://gist.github.com/deadbits/5428636

    Module include PySocks, a SocksiPy fork by Anorov
    https://github.com/Anorov/PySocks

    User-Agents samples taken from the Random Agent Spoofer by dbyrne
    https://github.com/dillbyrne/random-agent-spoofer
"""

__author__ = 'Vasily Asakasinsky'
__license__ = "MIT"
__version__ = "1.1.1"
__maintainer__ = "Vasily Asakasinsky"
__email__ = "asakasinsky@gmail.com"
__status__ = "Development"


import os
import sys
from random import choice
import time
import json

import socket
import socks

import cookielib

import urllib
from urllib2 import Request, urlopen, URLError, HTTPPasswordMgrWithDefaultRealm
from urllib2 import HTTPBasicAuthHandler, build_opener, install_opener
from urllib2 import HTTPRedirectHandler, HTTPCookieProcessor
from urllib2 import HTTPError


from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
import gzip






import requests
import requesocks

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCES_DIR = os.path.join(CURRENT_DIR, 'resources')
USER_AGENT_FILE = os.path.join(RESOURCES_DIR, 'user-agents.json')


class RedirectHandler(HTTPRedirectHandler):
    def __init__(self, follow=False):
        self.follow = follow

    def http_error_302(self, req, fp, code, msg, headers):
        if not self.follow:
            result = urllib.addinfourl(fp, headers, req.get_full_url())
            result.status = code
            result.code = code
            print 'REDIRECT STOPPED'
            return result
        else:
            # redirects = []
            # redirects.append(headers['location'])
            result = HTTPRedirectHandler.http_error_302(
                self, req, fp, code, msg, headers)
            result.status = code
            result.redirected = True
            print 'REDIRECTED %s' % (code)
            return result

    http_error_301 = http_error_303 = http_error_307 = http_error_302


class Troxy(object):
    """
    Urllib wrapper for HTTP requests via Tor socks5 proxy
    """
    def __init__(
        self,
        timeout=10,
        proxytype='SOCKS5',
        host='127.0.0.1',
        port=9150,
        control_port=9151,
        password='mypassword',
        follow_redirect=False
    ):
        self.proxytype = proxytype.lower()
        self.timeout = timeout
        self.host = host
        self.port = port

        self.control_port = control_port
        self.password = password

        self.regular_session = requests.Session()
        self.proxied_session = requesocks.session()

        self.session = None

        self.follow_redirect = follow_redirect

        self.cookie = cookielib.CookieJar()

        self.set(
            proxytype=self.proxytype,
            host=self.host,
            port=self.port,
        )
        self.off()

        self.running = False
        self.useragents = None
        self.__fingerprint_store = {}
        self.headers = {
            'User-Agent': 'Troxy',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
            'Accept-Language': 'en-US',
            'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
            'Accept-Encoding': 'gzip,deflate'
        }
        self.__load_useragents()

    def basic_auth(self, top_level_url=None, username=None, password=None,):
        if (not username or not password or not top_level_url):
            return False
        # create a password manager
        password_mgr = HTTPPasswordMgrWithDefaultRealm()

        # Add the username and password.
        # If we knew the realm, we could use it instead of ``None``.
        password_mgr.add_password(None, top_level_url, username, password)

        handler = HTTPBasicAuthHandler(password_mgr)

        # create "opener" (OpenerDirector instance)
        opener = build_opener(
            handler,
            RedirectHandler(
                follow=self.follow_redirect
            ),
            HTTPCookieProcessor(self.cookie)
        )
        install_opener(opener)

    def __load_useragents(self):
        try:
            f = open(USER_AGENT_FILE, 'r')
        except IOError:
            print('Cannot open file with user-agents samples')
            return False
        else:
            with f:
                self.useragents = json.load(f)['uadata']
                self.random_client()
                return True

    def random_client(self):
        """
        Setting random headers
        """
        return self.iam('any')

    def iam(self, name='any'):
        """
        Setting specific client headers
        """
        if not self.useragents:
            return False

        aliases = {
            'windows': 'Windows Browsers',
            'mac': 'Mac Browsers',
            'linux': 'Linux Browsers',
            'unix': 'Unix Browsers',
            'android': 'Android',
            'ios': 'iOS',
            'winphone': 'Windows Phone / Tablet',
            'spider': 'Spiders - Search',
            'console': 'Game Consoles',
            'library': 'Libraries',
            'misc': 'Miscellaneous',
        }
        platform = {}
        name = name.lower()
        if name == 'any':
                platform = choice(self.useragents)
        else:
            if name in aliases:
                for key in self.useragents:
                    if key['description'] == aliases[name]:
                        platform = key

        if not len(platform):
            return False
        sample = choice(platform['useragents'])
        self.headers = {
            'User-Agent': sample['useragent'],
            'Accept': sample['accept_default'],
            'Accept-Language': sample['accept_lang'],
            'Accept-Encoding': sample['accept_encoding'],

            # 'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
            'Keep-Alive': '115',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Referer': 'https://www.google.com/',
        }
        return True

    def __dns_patch(self, *args):
        """
        Magic patch for DNS over proxy
        """
        return [(
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            '',
            (args[0], args[1])
        )]

    def set(self, **kwargs):
        if len(kwargs):
            for key in kwargs:
                setattr(self, key, kwargs[key])
        self.proxied_session.proxies = {
            'http': '%s://%s:%s' % (
                self.proxytype,
                self.host,
                self.port
            ),
            'https': '%s://%s:%s' % (
                self.proxytype,
                self.host,
                self.port
            ),
        }

    def on(self, **kwargs):
        self.session = self.proxied_session
        self.running = True

    def off(self):
        self.session = self.regular_session
        self.running = False

    def is_tor(self):
        """
        Checks if tor is properly enabled
        """
        res = self.get(
            'https://check.torproject.org/'
        )['text']
        print res
        if res.find('This browser is configured to use Tor.') < 1:
            return False
        return True

    def newidentity(
        self
    ):
        """
        Control Tor via Telnet (socket):
        ================================
        You must create a hashed password out of your password using:
        tor --hash-password your-password

        Add to...
            Ubuntu/Debian:   /etc/tor/torrc
            OS X (homebrew): /usr/local/etc/tor/torrc

        ... this lines

        SocksPort 9150
        RunAsDaemon 1
        ControlPort 9151
        HashedControlPassword hashe-from-your-password
        CookieAuthentication 0
        """
        self.s = socket.socket()
        self.s.connect((
            self.host,
            self.control_port
        ))
        try:
            self.s.send('Authenticate "%s"\r\n' % self.password)
            if not '250' in self.s.recv(1024):
                raise ValueError('Authenticate error. Wrong password may be.')

            self.s.send('signal newnym\r\n')
            if not '250' in self.s.recv(1024):
                raise ValueError('New identity signal error')
        except ValueError, err:
            print err
        finally:
            self.s.close()
        self.random_client()
        print 'Wait for identity change...'
        time.sleep(10)
        print 'New identity - OK'
        return True

    def quit(self, msg=1):
        sys.exit(msg)

    def fingerprint(
            self,
            *fields,
            **opts
    ):
        """
        https://wiki.mozilla.org/Fingerprinting

        I'm using jsontest.com for getting fingerprint.

        Note:
        Is not the best way to get the information we need. Sometimes the ser-
        vice may not be available, and method returns None

        Usage:
        self.fingerprint( <key>, <key>, <key>, <option=True>, <option=True>)

        Where:
            <key> is key of received json ('ip', 'Accept-Language', etc)
            <option=True> is option from following list:
                plain:  fingerprint will return as plain-text
                html:   fingerprint will return as html

        As default, fingerprint will return as JSON dict.

        Example:
        self.fingerprint('user_agent', 'ip_addr', plain=True)
        """
        frmt = []
        indent = 0
        filtered_data = {}

        json_string = self.get(url='http://headers.jsontest.com/')['text']
        if json_string:
            try:
                self.__fingerprint_store = json.loads(json_string)
            except Exception:
                return None
        json_string = self.get(url='http://ip.jsontest.com/')['text']
        if json_string:
            try:
                self.__fingerprint_store['ip'] = json.loads(json_string)['ip']
            except Exception:
                return None
        else:
            return None

        if fields:
            for key in fields:
                if key in self.__fingerprint_store:
                    filtered_data[key] = self.__fingerprint_store[key]
        else:
            filtered_data = self.__fingerprint_store

        if 'plain' in opts:
            for key, value in filtered_data.iteritems():
                frmt.append(' ' * indent + str(key) + ':')
                frmt.append(' ' * (indent+2) + str(value) + '\n')
            return ''.join(frmt)

        elif 'html' in opts:
            frmt.append('<table class="b-fp"><tbody>')
            for key, value in filtered_data.iteritems():
                frmt.append('<tr class="fp-row">')
                frmt.append('<td class="fp-col-name">' + str(key) + ':</td>')
                frmt.append('<td class="fp-col-val">' + str(value) + '</td>')
                frmt.append('</tr>')
            frmt.append('</tbody></table>')
            return ''.join(frmt)

        else:
            return filtered_data

    def set_headers(self, headers=None):
        """
        Setting HTTP headers
        """
        if type(headers) is dict:
            self.headers = headers

    def __response_tpl(self):
        return {
            'code': 0,
            'message': {
                'short': '',
                'long': ''
            },
            'url': '',
            'info': {},
            'text': '',
            'redirected': False,
            'error': None,
            'raw': None
        }

    def __message_obj(self, code):
        # BaseHTTPServer.BaseHTTPRequestHandler.responses is a useful
        # dictionary of response codes in that shows all the response
        # codes used by RFC 2616. The dictionary is reproduced here for
        # convenience
        # Table mapping response codes to messages; entries have the
        # form {code: (shortmessage, longmessage)}.
        message = {}
        if code in BaseHTTPRequestHandler.responses:
            message['short'] = BaseHTTPRequestHandler.\
                responses[int(code)][0]
            message['long'] = BaseHTTPRequestHandler.\
                responses[int(code)][1]
        return message

    def __request(self, method='GET', url='', data={}):
        response = self.__response_tpl()
        req = getattr(
            self.session,
            method.lower()
        )

        try:
            r = req(
                url,
                data=data,
                headers=self.headers,
                allow_redirects=self.follow_redirect,
                timeout=self.timeout
            )
            response['text'] = r.text
            response['code'] = r.status_code
        except Exception as e:
            print 'Error: %s' % (e)
        return response

    def get(self, url='', data=None):
        """
        HTTP GET method.
        """
        # if not data:
        #     return "There are not POST data"
            # data = urllib.urlencode(data)
            # url = url+'?'+data
        # req = Request(url=url)
        # return self.__request(req)
        # self.session.headers.update(self.headers)
        return self.__request(
            method='GET',
            url=url,
            data=data
        )

    def post(self, url='', data=None):
        """
        HTTP POST method.
        """
        if not data:
            return "There are not POST data"
        # data = urllib.urlencode(data)
        # req = Request(url=url)
        # req.add_data(data)
        # return self.__request(req)

        # self.session.headers.update(self.headers)
        return self.__request(
            method='POST',
            url=url,
            data=data
        )

"""
https://github.com/tarampampam/random-user-agent/blob/master/background.js
"""
