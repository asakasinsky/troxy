# Troxy

_Awesome module for HTTP requests via Tor socks5 proxy_


**Features:**

- DNS via Tor proxy. _sorry, not yet tested in current version_
- GET, POST requests via Tor proxy
- GZIP support
- Identity change (IP, User-Agent, etc)
- Setting specific headers

Original idea by [deadbits](https://gist.github.com/deadbits/5428636)  

User-Agents samples taken from the [Random Agent Spoofer by dbyrne](https://github.com/dillbyrne/random-agent-spoofer)

**Usage:**

```python
from troxy import Troxy
proxy = Troxy()
```


...or:
```python
proxy = Troxy(
    timeout=10,
    host='127.0.0.1',
    port=9150,
    control_port=9151,
    password='mypassword',
    follow_redirect=True
)
```


Enable proxy and test it:
```python
proxy.on()
if proxy.is_tor():
    print('tor proxy running!')
    print proxy.fingerprint('ip')
```


Get web fingerprint:

```python
# args is a keys of received json
# ('Accept-Language', 'Host', 'User-Agent', 'Accept', 'ip')
#
# options: plain=True:  fingerprint will return as plain-text
#          html=True:   fingerprint will return as html

print proxy.fingerprint()
print proxy.fingerprint('ip', 'User-Agent')
print proxy.fingerprint('ip', 'User-Agent', plain=True)
```



You can set another proxy on «fly». Strongly recomended use SOCKS5 proxy because only via SOCKS5 DNS can be sended.
```python
proxy.set(
    proxytype='SOCKS5',
    host='61.147.67.2',
    port=9123,
)
print proxy.fingerprint('ip')
```


You can set random headers:
```python
print proxy.fingerprint()
proxy.random_client()
print proxy.fingerprint()
```


You can set specific headers:
```python
"""
Aliases: 
    windows, mac, linux, unix, android, ios, 
    winphone, spider, console, library, misc
"""
proxy.iam('ios')
print proxy.headers
```


Basic-Auth:
```python
proxy.basic_auth(
    top_level_url="http://example.com/private/",
    username='username',
    password='password'
)
```


HTTP GET request:
```python
print proxy.get(url='http://example.com/')
```


HTTP POST request
```python
post_data = {'test': 'test value'}
print proxy.post(url='http://example.com/', data=post_data)
```



New identity (Tor feature):
```python
newidentity = proxy.newidentity()
if not newidentity:
    print('Failed to get new identity!')
print proxy.fingerprint('ip')
```


Disable proxy now:
```python
proxy.off()
print proxy.fingerprint('ip')
```


Parsing html via proxy with LXML
```python
import lxml.html as lh
res = proxy.get(url='https://github.com/')['body']
doc = lh.fromstring(res)
print doc.xpath('//h1[@class="heading"]/text()')[0]
```

... or
```python
from lxml import etree
tree = etree.HTML(proxy.get(url='https://github.com/')['body'])
print tree.xpath('//h1[@class="heading"]/text()')[0]
```
