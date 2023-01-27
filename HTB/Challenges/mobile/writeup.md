# HTB Cat [EASY]

## Android backup

This backup is from android, which is needed to extract and find flag.


## Start

First we run ```file``` command against 'cat.ab' file:

```cat.ab: Android Backup, version 5, Compressed, Not-Encrypted```

"Not-Encrytped", cool. So we can unpack this backup and see whats inside of it.

## ABE

For this, we use Android Backup Extractor to get this backup unpacked:

```java -jar abe.jar unpack ./cat.ab ./backup.tar```

Now just extract tar packet:

```tar -xvf ./backup.tar``` and now we have this android backup open!

There was 2 folders: apps and shared. 

Going to ./shared/0/Pictures/ we can find some images of CATS! wow.

Opening images one by one, we can see some guy holdin TOP SECRET papers, and very bottom there is our flag: ```HTB{****}```