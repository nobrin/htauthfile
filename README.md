htauthfile: Utility for basic htpasswd with pure Python
==========

## Overview

Basic authentication is one of simple authentication on http.
This module provides easy way for modifing htpasswd file.

## Usage

```
>>> import htauthfile
>>> ht = htauthfile.Basic("siteuser.htpasswd")
>>> print ht.authenticate("user1", "password")
True
>>> ht.update("user1", "newPassword")
>>> ht.save("siteuser.htpasswd")
```

