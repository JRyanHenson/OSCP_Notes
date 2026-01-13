---
tags: [ProvingGround]
---

Wombo 5/15/25

-------------------------

## 1.

Nmap scan report for 192.168.208.69

PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey:
|   2048 09:80:39:ef:3f:61:a8:d9:e6:fb:04:94:23:c9:ef:a8 (RSA)
|   256 83:f8:6f:50:7a:62:05:aa:15:44:10:f5:4a:c2:f5:a6 (ECDSA)
|_  256 1e:2b:13:30:5c:f1:31:15:b4:e8:f3:d2:c4:e8:05:b5 (ED25519)
53/tcp    closed domain
80/tcp    open   http       nginx 1.10.3
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.3
6379/tcp  open   redis      Redis key-value store 5.0.9
8080/tcp  open   http-proxy
|_http-title: Home | NodeBB
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=3FmI6rVctZmshS4k9oCMDaS9; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 11098
|     ETag: W/"2b5a-/QmLvyfifTWGoQK2y2sGV54TLvE"
|     Vary: Accept-Encoding
|     Date: Wed, 14 May 2025 20:33:02 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Not Found | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_n
|   GetRequest:
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=9k2QlDRSardSeNi3VD3dk98h; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 18181
|     ETag: W/"4705-wfBQr0BJQfsACEO3RPQMDFKrOuc"
|     Vary: Accept-Encoding
|     Date: Wed, 14 May 2025 20:33:02 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Home | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_name" content
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Vary: Accept-Encoding
|     Date: Wed, 14 May 2025 20:33:02 GMT
|     Connection: close
|     GET,HEAD
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request
|_    Connection: close
| http-robots.txt: 3 disallowed entries
|_/admin/ /reset/ /compose
27017/tcp open   mongodb    MongoDB 4.0.18 4.1.1 - 5.0
| mongodb-info:
|   MongoDB Build info
|     sysInfo = deprecated
|     debug = false
|     allocator = tcmalloc
|     storageEngines
|       3 = wiredTiger
|       0 = devnull
|       1 = ephemeralForTest
|       2 = mmapv1
|     javascriptEngine = mozjs
|     versionArray
|       3 = 0
|       0 = 4
|       1 = 0
|       2 = 18
|     bits = 64
|     ok = 1.0
|     maxBsonObjectSize = 16777216
|     modules
|     buildEnvironment
|       ccflags = -fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -Werror -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -fno-builtin-memcmp
|       cxx = /opt/mongodbtoolchain/v2/bin/g++: g++ (GCC) 5.4.0
|       target_os = linux
|       distarch = x86_64
|       target_arch = x86_64
|       distmod = debian92
|       linkflags = -pthread -Wl,-z,now -rdynamic -Wl,--fatal-warnings -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro
|       cxxflags = -Woverloaded-virtual -Wno-maybe-uninitialized -std=c++14
|       cc = /opt/mongodbtoolchain/v2/bin/gcc: gcc (GCC) 5.4.0
|     gitVersion = 6883bdfb8b8cff32176b1fd176df04da9165fd67
|     openssl
|       running = OpenSSL 1.1.0l  10 Sep 2019
|       compiled = OpenSSL 1.1.0l  10 Sep 2019
|     version = 4.0.18
|   Server status
|     errmsg = command serverStatus requires authentication
|     ok = 0.0
|     codeName = Unauthorized
|_    code = 13
| mongodb-databases:
|   errmsg = command listDatabases requires authentication
|   ok = 0.0
|   codeName = Unauthorized
|_  code = 13

## 2. Was able to connect to redis server using redis-cli -h 192.168.208.69 -p 6379
## 3. Tried a number of redis manual hacks found at https://github.com/Ridter/redis-rce?tab=readme-ov-file
## 4. Found exploit for redis https://github.com/n0b0dyCN/redis-rogue-server/tree/master - I was successful after changing local port to 8080.