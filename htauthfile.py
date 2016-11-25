# -*- coding: utf-8 -*-
"""
Utility for basic htpasswd with pure Python.

Basic authentication is one of simple authentication on http.
This module provides easy way for modifing htpasswd file.

Example::

    >>> import htauthfile
    >>> ht = htauthfile.Basic("siteuser.htpasswd")
    >>> print ht.authenticate("user1", "password")
    True
    >>> ht.update("user1", "newPassword")
    >>> ht.save("siteuser.htpasswd")
"""

__author__ = "Nobuo Okazaki"
__version__ = "0.1.0"
__license__ = "MIT License"

import re, random, string
from collections import OrderedDict

class Basic(object):
    def __init__(self, authfile=None):
        # If authfile is specified, load it after initialize.
        self.user = OrderedDict()
        self.authfile = None
        if authfile: self.load(authfile)

    def load(self, authfile):
        # Load htpasswd file.
        self.user = OrderedDict()
        with open(authfile) as fh:
            lno = 0
            for line in fh:
                lno += 1
                if line.startswith("#"): continue
                items = line.strip().split(":")
                if len(items) != 2:
                    raise RuntimeError("Invalid format line %d: %s" % (lno, line.rstrip()))
                self.user[items[0]] = {"digest": items[1]}
        self.authfile = authfile

    def save(self, authfile):
        # Write out htpasswd file.
        with open(authfile, "wb") as fh:
            for k, v in self.user.items():
                fh.write("%s:%s\n" % (k, v["digest"]))

    def authenticate(self, username, text):
        # Authenticate username and text(plain password).
        if username not in self.user:
            raise ValueError("Specified user does not exist")
        digest = self.user[username]["digest"]
        typename = self.get_digest_type(digest)
        func = getattr(self, "generate_%s" % typename)
        return (digest == func(text, digest))

    def update(self, username, password):
        # Update password for username.
        if username not in self.user:
            raise ValueError("User %s is not in DB." % username)

        typename = self.get_digest_type(self.user[username]["digest"])
        self.user[username] = {"digest": getattr(self, "generate_%s" % typename)(password)}

    def add(self, username, password, typename="crypt"):
        # Add user
        if username in self.user:
            raise ValueError("User %s is already in DB." % username)
        self.user[username] = getattr(self, "generate_%s" % typename)(password)

    def get_digest_type(self, digest):
        # Get digest type
        # https://httpd.apache.org/docs/2.2/misc/password_encryptions.html
        if digest.startswith("$apr1$"):
            if digest.split("$"): return "apr1"
            raise ValueError("Invalid format with '$apr1$': %s" % digest)
        if digest.startswith("{SHA}"): return "sha1"
        if re.match(r"[0-9a-zA-Z\.]{13}$", digest): return "crypt"
        raise ValueError("Invalid format: %s" % digest)

    def generate_sha1(self, pw, salt=None):
        raise NotImplementedError()

    def generate_crypt(self, pw, salt=None):
        # Generate digest string with CRYPT()
        import crypt
        salt = salt or "".join([random.choice(string.ascii_letters + string.digits + "./") for i in range(2)])
        return crypt.crypt(pw, salt)

    def generate_apr1(self, pw, salt=None):
        """Generate digest string for Apache apr1

        Ref. How to programmaticaly build an APR1-MD5 using PHP
        http://stackoverflow.com/questions/1038791/how-to-programmaticaly-build-an-apr1-md5-using-php

        [2013-11-30] Translate from this function
        function crypt_apr1_md5($plainpasswd) {
            $salt = substr(str_shuffle("abcdefghijklmnopqrstuvwxyz0123456789"), 0, 8);
            $len = strlen($plainpasswd);
            $text = $plainpasswd.'$apr1$'.$salt;
            $bin = pack("H32", md5($plainpasswd.$salt.$plainpasswd));
            for($i = $len; $i > 0; $i -= 16) { $text .= substr($bin, 0, min(16, $i)); }
            for($i = $len; $i > 0; $i >>= 1) { $text .= ($i & 1) ? chr(0) : $plainpasswd{0}; }
            $bin = pack("H32", md5($text));
            for($i = 0; $i < 1000; $i++) {
                $new = ($i & 1) ? $plainpasswd : $bin;
                if ($i % 3) $new .= $salt;
                if ($i % 7) $new .= $plainpasswd;
                $new .= ($i & 1) ? $bin : $plainpasswd;
                $bin = pack("H32", md5($new));
            }
            for ($i = 0; $i < 5; $i++) {
                $k = $i + 6;
                $j = $i + 12;
                if ($j == 16) $j = 5;
                $tmp = $bin[$i].$bin[$k].$bin[$j].$tmp;
            }
            $tmp = chr(0).chr(0).$bin[11].$tmp;
            $tmp = strtr(strrev(substr(base64_encode($tmp), 2)),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
            return "$"."apr1"."$".$salt."$".$tmp;
        }
        """
        alphabets = string.digits + string.letters
        salt = salt or ''.join(random.choice(alphabets) for i in xrange(8))

        text = "%s$apr1$%s" % (pw, salt)
        bin = hashlib.md5(pw + salt + pw).digest()
        for i in range(len(pw), 0, -16): text += bin[0:min(16, i)]

        i = len(pw)
        while i > 0:
            text += chr(0) if (i & 1) else pw[0]
            i >>= 1
        bin = hashlib.md5(text).digest()

        for i in xrange(1000):
            new = pw if (i & 1) else bin
            if i % 3: new += salt
            if i % 7: new += pw
            new += bin if (i & 1) else pw
            bin = hashlib.md5(new).digest()

        tmp = ""
        for i in xrange(5):
            k = i + 6
            j = i + 12
            if j == 16: j = 5
            tmp = bin[i] + bin[k] + bin[j] + tmp

        tmp = chr(0) + chr(0) + bin[11] + tmp
        rev = base64.b64encode(tmp)[2:][::-1]
        tr = string.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        )
        return "$apr1$%s$%s" % (salt, rev.translate(tr))
