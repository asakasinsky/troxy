# Troxy

_Awesome module for HTTP requests via Tor socks5 proxy_


**Features:**

- DNS via Tor proxy
- GET, POST requests via Tor proxy
- GZIP support
- Identity change (IP, User-Agent, etc)
- Setting specific headers

Original idea by [deadbits](https://gist.github.com/deadbits/5428636)  

Module include PySocks, a [SocksiPy fork by Anorov](https://github.com/Anorov/PySocks)

User-Agents samples taken from the [Random Agent Spoofer by dbyrne](https://github.com/dillbyrne/random-agent-spoofer)

**Usage:**

```python
from troxy import Troxy
proxy = Troxy()
```


Enable proxy and test it:
```python
proxy.on()
if proxy.is_tor:
    print('tor proxy running!')
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


Get web fingerprint:
```python
print proxy.fingerprint('ip', 'User-Agent', update=True)
```


Set random headers:
```python
proxy.random_client()
print proxy.headers
```


Set specific headers:
```python
"""
Aliases: 
    windows, mac, linux, unix, android, ios, 
    winphone, spider, console, library, misc
"""
proxy.iam('ios')
print proxy.headers
```


New identity:
```python
newidentity = proxy.newidentity(
    password='mypassword',
    random_client=False
)
if not newidentity:
    print('Failed to get new identity!')
print proxy.fingerprint('ip', update=True)
```


Disable proxy:
```python
proxy.off()
print proxy.fingerprint('ip', update=True)
```


Parsing html via proxy with LXML
```python
import lxml.html as lh
res = proxy.get(url='http://stackoverflow.com/')
doc = lh.fromstring(res)
print doc.xpath('//div[@id="hlogo"]/a/text()')[0]
```
