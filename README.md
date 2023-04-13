# WSCS-Assignment-1

Document: https://docs.google.com/document/d/1vmRyLAGnHboLolYdWpB8hqrVOGIXYYdh_8O-xh4_D7E/edit


## Prerequisites

```
python==3.8
hashlib==1.3.1
flask==2.2.3
redis==4.5.4
```

## Run Urlkv

1. Start redis server in terminal

```
$ redis-server
```

2. Run Urlkv.py

```
python3 Urlkv.py
```

## Regex expression

The regex expression for URL Validation is from https://github.com/django/django/blob/stable/1.3.x/django/core/validators.py#L45

The regular expression is broken down into several parts:

1. `^(?:http|ftp)s?://`: This part of the pattern matches the start of the URL. The `^` character matches the start of the string. The `(?:http|ftp)` part matches either `http` or `ftp`. The `s?` part matches an optional `s` character (for `https` or `ftps`). Finally, the `://` part matches the characters `://`.

2. `(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|`: This part of the pattern matches the domain name of the URL. It can match domain names with multiple subdomains separated by dots. The domain name can contain letters, numbers, and hyphens. The top-level domain can be between 2 and 6 characters long or it can be a longer string containing letters, numbers, and hyphens.

3. `localhost|`: This part of the pattern matches the string `localhost`.

4. `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`: This part of the pattern matches an IP address. It consists of four groups of digits separated by dots. Each group of digits can be between 1 and 3 digits long.

5. `(?::\d+)?`: This part of the pattern matches an optional port number. The port number must be preceded by a colon and can consist of one or more digits.

6. `(?:/?|[/?]\S+)$`: This part of the pattern matches the path and query string of the URL. The path can be empty or it can start with a `/` character. The query string must start with a `?` character and can contain any non-whitespace characters.

The regular expression is compiled with the `re.IGNORECASE` flag which makes it case-insensitive.
