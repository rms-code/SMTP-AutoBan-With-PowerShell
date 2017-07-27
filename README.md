 Check the bottom of the page for any updates
-----



 

Over the last year, I have noticed at my job a lot more ‘poking’, be it banner grabs, AUTH LOGIN/AUTH NTLM attempts for directory-type attacks/harvesting, or the odd open-relay try; mostly from bots or scanners, while we don’t allow plain-text, nor reply back to directory-type attacks if a user does/doesn't exist, there are still timing attacks that could be used, now I don’t think that is really the case here, but I thought to myself how can we stop these types of scans being further used/tried repeatedly(which they do, 100’s of times sometimes). Because most of these are just connect/disconnect, or a simple auth login/ntlm username for harvesting/info gathering, most go under the radar as it isn't anything actually being sent.

 

One thing I noticed in the SMTP Protocol Logs (you do have those turned on verbose, right?) was that 100% of the time, any type of these occurrences showed the same thing, none of them could reply back with an FQDN, now I know there are more sophisticated ways and easy enough to have a cert/TLD reply, but one step at a time.

 

 

Here is an example of a few SMTP Protocol lines filtered out to see easier.

```
2016-12-14T10:06:17.792Z,EX\Default ,0000000000000000,3,x.x.x.x:25,85.52.201.139:3180,<,EHLO ylmf-pc,

2016-12-14T10:34:37.000Z,EX\Default ,0000000000000000,3,x.x.x.x:25,203.45.228.110:54190,<,EHLO ylmf-pc,

2016-12-14T22:38:44.739Z,EX\Default ,0000000000000000,3,x.x.x.x:25,137.118.101.85:35517,<,EHLO rVySze,

2016-12-14T22:38:46.833Z,EX\Default ,0000000000000000,3,x.x.x.x:25,69.46.250.100:46314,<,EHLO lBgQqRe,

2016-12-14T22:38:53.661Z,EX\Default ,0000000000000000,3,x.x.x.x:25,204.221.17.75:36091,<,EHLO masscan,
```

ylmf-pc is a large botnet out in the world, it spams servers with AUTH LOGIN tries, the other 2 are bots, and the last one is probably just as it says, some large scan doing banner grabs.

 

We log and monitor message tracking/agent logs from exchange, as well as AD EventID's (good/bad, user/pc name, lockouts, too many tries on account, etc) with alert streams from graylog, the reason I started to notice this was the random username tries from the AD logs, but AD logs don’t have external IP addresses; just the username with a transient identifying the internal server, so this begun my smtp protocol log search.

 

We first started just running wireshark/netmon but that took up a lot of memory, even the CLI versions, plus it wasn't really fun to do it manually, and by then it could of been going for 7 hours while we all sleep.

 

I will try to go step by step on howto implement this, or engineer it to suit your env/vendor of firewall, I would imagine most have CLI that you can use the same invoke-ssh cmdlets, you would just have to figure out your CLI commands to suit that vendor.

 

First, the things you need, or atleast something that is close to the same type of function.

 

OPTIONAL - Graylog(v1.2 and 2.1 work fine)
nxlog(or if you want, some type of log shipper that allows you to use regex)
Exchange 2010(2013/2016 will work, just find your log path as it is different between them, and change config)
Fortigate Firewall/$Vendor firewall, but that's on you. (firmware 5.2.x, I have not tested this on 5.4.x, input would be welcomed!)
Posh-SSH module / PS v3+
 

Everything should be pretty straight forward, I will assume you have installed graylog, nxlog installed on your exchange box, access to a fortigate(or if you are going to change that part, your $vendor firewall).

 

I will 100% say you should use Graylog, it is great for visualizing data, creating streams from the data sets you give it, and build streams off those datasets, and metrics over time.

 

Posh-SSH install is easy, please go to:

https://github.com/darkoperator/Posh-SSH and follow the page.

 


 

Let’s get the logs rolling

 

For an idea, lets look at a small smtp protocol log sample.

```
2016-12-14T01:17:34.808Z,EX\Default ,0000000000000000,0,x.x.x.x:25,91.112.61.94:55171,+,,

2016-12-14T01:17:34.808Z,EX\Default ,0000000000000000,1,x.x.x.x:25,91.112.61.94:55171,*,SMTPSubmit SMTPAcceptAnySender SMTPAcceptAuthoritativeDomainSender AcceptRoutingHeaders,Set Session Permissions

2016-12-14T01:17:34.808Z,EX\Default ,0000000000000000,2,x.x.x.x:25,91.112.61.94:55171,>,"220 mail.x.x Microsoft ESMTP MAIL Service ready at Tue, 13 Dec 2016 20:17:34 -0500",

2016-12-14T01:17:36.340Z,EX\Default ,0000000000000000,3,x.x.x.x:25,91.112.61.94:55171,<,EHLO ylmf-pc,

2016-12-14T01:17:36.340Z,EX\Default ,0000000000000000,4,x.x.x.x:25,91.112.61.94:55171,>,250-mail.x.x Hello [91.112.61.94],

2016-12-14T01:17:36.340Z,EX\Default ,0000000000000000,5,x.x.x.x:25,91.112.61.94:55171,>,250-SIZE,

2016-12-14T01:17:36.340Z,EX\Default ,0000000000000000,6,x.x.x.x:25,91.112.61.94:55171,>,250-PIPELINING,

2016-12-14T01:17:36.340Z,EX\Default ,0000000000000000,7,x.x.x.x:25,91.112.61.94:55171,>,250-DSN,

2016-12-14T01:17:36.340Z,EX\Default ,0000000000000000,8,x.x.x.x:25,91.112.61.94:55171,>,250-ENHANCEDSTATUSCODES,

2016-12-14T01:17:36.340Z,EX\Default ,0000000000000000,9,x.x.x.x:25,91.112.61.94:55171,>,250-STARTTLS,

2016-12-14T01:17:36.340Z,EX\Default ,0000000000000000,10,x.x.x.x:25,91.112.61.94:55171,>,250-AUTH NTLM,

2016-12-14T01:17:36.340Z,EX\Default ,0000000000000000,11,x.x.x.x:25,91.112.61.94:55171,>,250-8BITMIME,

2016-12-14T01:17:36.340Z,EX\Default ,0000000000000000,12,x.x.x.x:25,91.112.61.94:55171,>,250-BINARYMIME,

2016-12-14T01:17:36.340Z,EX\Default ,0000000000000000,13,x.x.x.x:25,91.112.61.94:55171,>,250 CHUNKING,

2016-12-14T01:17:36.496Z,EX\Default ,0000000000000000,14,x.x.x.x:25,91.112.61.94:55171,<,AUTH LOGIN,

2016-12-14T01:17:36.496Z,EX\Default ,0000000000000000,15,x.x.x.x:25,91.112.61.94:55171,*,Tarpit for '0.00:00:05',

2016-12-14T01:17:41.496Z,EX\Default ,0000000000000000,16,x.x.x.x:25,91.112.61.94:55171,>,504 5.7.4 Unrecognized authentication type,

2016-12-14T01:17:42.074Z,EX\Default ,0000000000000000,17,x.x.x.x:25,91.112.61.94:55171,-,,Remote
```

 When you forward smtp protocol to graylog, each LINE is one LOG FILE—doesn’t really work great for us for a total log, nor does it work well to use for getting just the IP of the source.

 
##### Let’s do a short breakdown of what is happening within the nxlog config file(grab it from repo)
=======================================================================================
 

We use multi-line to try and group these into one log section, it isn’t pretty, and it doesn’t always work out, if anyone has a better idea or regex-fu, please help in this area, for now we have:

 



 

 

 

 

 

 

The next step is to cut a logfile and drop every line that doesn’t have an ‘ehlo’ on it insensitive so it catches [Aa], we use completelog.txt for graylog as well as the next part:

 



 

 

 

Next part is we run regex against the completelog, and tell it to drop anything that has a TLD on that ehlo line, output to a new noTLD.txt logfile:

 

 



 

 

 

 

On the output file for notld.txt, add some exclusions like internal relays, etc:

 

 



 

 



 

Quick logfile breakdown now:

 
```
Completelog.txt – all lines with ehlo
notld.txt – ONLY ehlo lines with no TLD
metriclogs.txt – total SMTP Protocol log, cut into divided sections, sort of :D
 ```

Good, lets move on!

 


Now that we have the logfile breakdown, I will explain the powershell code.

 

 

#### Let’s ban some bots!

 

Let's take a look at the powershell code that will run every 5 minutes.

Note, if there is a better way please let me know; As for fortigate units, there is an object limit of 10,000, and 300 objects per-object group until you get to a larger units.

 the $iplist variable is used to get the content of the notld.txt which will have strings like mentioned at the start of the post, we need to filter out everything but the incoming IP, i decided to use the 'sort of' CSV breakdown in the log to do this, basically matching everything between the selected comma's, stopping at the first ":" and adding /32 at the end-- the reason we need this is for the fortigate, it requires the subnet for the IP being added, so its easier to just do this now, we then pipe this to the lovely cmdlet of sort -unique, which does what it says.

 
```
%{ if ($_ -imatch '^(?:[^,]*\,){5}(...(?:[^:]*){1})(?:[^\s]*\s){1}(...(?:[^,]*))') {($matches[1] -ireplace "$", "/32")} } | sort -Unique
```
 

The rest of the variables should be pretty self explanatory, $appmem is used to add an object if a new object-group is needed to be created, i used a private IP in a range we will never use, and because its External > Internal, no big deal.

 

New-SSHSession is used to create a session with your firewall, make sure SSH is enabled for Internal port only, and also just as a side note, make sure your admin accounts are locked down to specific subnets.

 

The first IF statement makes sure we have a SSH Session ID that we made above, we create a stream to get the address groups and put that into a text file, put that into its own variable do run a match and replace for groups that are digits only(explained below), we then put that into an array and pipe this into a measure cmdlet, selecting this and putting it into a file, we then use another get-content for that text file(which will have the 'highest' group number ie: 1, or 2, 3 depending how many are filled up, remember our limit), we then invoke a firewall command to give us all the members of that group, and output that to a file, putting that into a variable and doing a count on that!

 

We need all this information to make sure we don't go past the fortigate limit of 300 objects per group.

 

The reason I did this was more because I was well... lazy a bit, so the GROUP NAME we use/check are 1,2,3 and so on, you could use an actual name and do your own calculation/regex match/replace.

 

Now the next IF statement we do some basic math on $ipcount and $iplistcount if it more than 299 objects, lets take the array info from above, add +1 to that number, and invoke a few CLI commands; creating a new object-group(using that $appmem variable) then the second invoke command needs to fit your env:

 



 The "edit 12`r" part, that is editing policy ID 12 on our test firewall this needs to be changed to whichever ID you are using for the 'DENY ALL' WAN > LAN policy.

 

The foreach invoke commands are obviously the same for the if/else, we use the CLI commands to add all the IPs from the $iplist file(notld.txt) and using the array we built earlier to know which object-group to add to.

 

At the end, we kill any session 0,1,2 just to make sure there wasn't other sessions in use or a bug to clear it out.

 

I added some extra log files for metrics, which is optional, I take the $iplist and add-content to a file, which will only give the unique ips each time from notld.txt, we then clear-content for the notld.txt so everytime it runs we have a fresh log file to read from.

 

Now for the automation part, set this up with task scheduler to run every 5 minutes, as the nxlog will poll around the same, this should be pretty straight forward using any built-in or other windows task schedulers.

 

The next part for graylog is again optional, but in my opinion it is silly to do all this, and not have it visualized, alerted, and give you the ability to build metrics off all this beautiful information.

#### GrayLog 
-------
So, we have all the EHLO lines being forwarded to graylog, we also have the metrics(full SMTP logs broken down), I wont be going into the metrics part in this post, because that's probably a post on its own, but I will help you out with the visualizing the data we send for all the EHLO lines (good and bad) and you can play around with filtering it out using regex or grok or however you like afterwards :)

![regex code](https://static.wixstatic.com/media/e67f27_3fb4bf0409d64cc3aa292e3fd9a87b63~mv2.jpg/v1/fill/w_550,h_177,al_c,q_80,usm_0.66_1.00_0.01/e67f27_3fb4bf0409d64cc3aa292e3fd9a87b63~mv2.webp)

Alright, so goto your input tab under system and show all messages from that log input you setup for this, once you see the data open up a full message and it should look like one of the lines from the beginning of the post, we want to "Regex and Replace", put in the above and you should then get a field called SMTPProtocolIPHOST, click on that and do a quick values on it, depending on your timeframe(at the top) it should give you all the IP's and Host's in the last X amount of time.
 
What it should look like, this was just a sample over 5 minutes for all EHLO, you can filter out noTLD, etc.
![graylog stuff](https://static.wixstatic.com/media/e67f27_f2a20f72bd9646c79592654c9f343b82~mv2.jpg/v1/fill/w_550,h_128,al_c,q_80,usm_0.66_1.00_0.01/e67f27_f2a20f72bd9646c79592654c9f343b82~mv2.webp)

Now you can play around with this, change the regex, its really how you want to see.
 
This isn't ment to be the only layer in your defense, but it should help improve some of the annoying pokes and bots from coming back to your systems, it also isn't perfect because I am sure eventually those IP's will be used for legit systems, but that's why we keep logs, incase of a false positive down the road, we can easily remove, and look up what that system used to do or try.

# UPDATES

NXLOG:
 
the notld.txt OUTPUT regex;
`^(?:[^,]*\,){7}(ehlo|helo)(?:[^\.|\[]*\.)`
 
This should also find servers that do not resolve to a FQDN
 
`   Exec       if $raw_event !~ /\b(User Name:)/i drop();`
 
The above will also add to the notld.txt for NTLM/shitty user tries that don't exist.
 
I will be releasing OWA Protection that pipes into this project in the next month or so.