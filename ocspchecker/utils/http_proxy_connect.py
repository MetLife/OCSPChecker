"""
Establish a socket connection through an HTTP proxy.
Author: Fredrik Østrem <frx.apps@gmail.com>
License:
  Copyright 2013 Fredrik Østrem
  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
  documentation files (the "Software"), to deal in the Software without restriction, including without
  limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
  Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
  The above copyright notice and this permission notice shall be included in all copies or substantial portions
  of the Software.
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
  TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
  CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
  DEALINGS IN THE SOFTWARE.
"""

# This file is a copy-paste from https://gist.github.com/frxstrem/4487802
#
# Some fixes were made:
# - remove long since it's just int in python3 (https://gist.github.com/frxstrem/4487802#file-http_proxy_connect-py-L46)
# - replace r+ with rw (https://gist.github.com/frxstrem/4487802#file-http_proxy_connect-py-L73)
# - fix b64encode, as stated in comments (https://gist.github.com/frxstrem/4487802?permalink_comment_id=3635597#gistcomment-3635597)
#
# Some refactors were made:
# - Typing of function arguments
# - Remove type validation of arguments & refactor auth checks to asign proxy-authorization header
# - Make proxy mandatory and remove case where the proxy == None
# - Remove the headers argument, since it's directly overwritten
# - Accept a socket instance to allow custom configuration
# - Return only the socket instance


import socket
from base64 import b64encode
from typing import Tuple, Union


def http_proxy_connect(
    address: Tuple[str, int],
    proxy: Tuple[str, int],
    auth: Union[None, str, Tuple[str, str]] = None,
    soc: Union[None, socket.socket] = None,
) -> socket.socket:
    """Establish a socket connection through an HTTP proxy."""

    headers = {"host": address[0]}

    if isinstance(auth, str):
        headers["proxy-authorization"] = auth
    elif isinstance(auth, tuple):
        headers["proxy-authorization"] = "Basic " + b64encode(
            ("%s:%s" % auth).encode("utf-8")
        ).decode("utf-8")

    s = soc if soc is not None else socket.socket()
    s.connect(proxy)
    fp = s.makefile("rw")

    fp.write("CONNECT %s:%d HTTP/1.0\r\n" % address)
    fp.write("\r\n".join("%s: %s" % (k, v) for (k, v) in headers.items()) + "\r\n\r\n")
    fp.flush()

    statusline = fp.readline().rstrip("\r\n")

    if statusline.count(" ") < 2:
        fp.close()
        s.close()
        raise IOError("Bad response")
    version, status, statusmsg = statusline.split(" ", 2)
    if not version in ("HTTP/1.0", "HTTP/1.1"):
        fp.close()
        s.close()
        raise IOError("Unsupported HTTP version")
    try:
        status = int(status)
    except ValueError:
        fp.close()
        s.close()
        raise IOError("Bad response")

    response_headers = {}

    while True:
        tl = ""
        l = fp.readline().rstrip("\r\n")
        if l == "":
            break
        if not ":" in l:
            continue
        k, v = l.split(":", 1)
        response_headers[k.strip().lower()] = v.strip()

    fp.close()
    return s
