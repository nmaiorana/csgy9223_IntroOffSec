# CSGY 9223 Intro to Offensive Security
# Week 13 Challenges
# nam10102

## Challenge - Super Secure Letter
```
I've strongly encrypted this super secure secret! 

See if you can recover the message using the ciphertext letter 
nc offsec-chalbroker.osiris.cyber.nyu.edu 1517
```
Running the binary with a flag.txt file:
```
./super_secure_letter
Here's my super secure letter! Good luck reading it :)!
d8af3421e307513cb5ca5144
```

Using binja to see what the binary does.

This looks pretty straight forward. The server reads the flag from the disk, and then encrypts each byte using a pseudo random number generator seeded with the current time squared. A new random number is selected for each character of the flag string.

Each byte is then returned as the hex value of the least significant two bytes. The value is printed out and needs to be decrypted.

The first is to grab each pair of character values returned and convert them to an integer. And with a synchronized random number generator in the solver script, XOR each value to reveal that character of the flag. Continue doing this until the entire flag is revealed.

To synchronize the time values, this was run three or four times. I did add an adjustment parameter, but this was not used when the flag was revealed.

```
Flag: flag{p3rh4p5_n07_50000_53cur3:(_4189ede7292d0f63}
```

## Challenge - Pseudo Rand
```
There's zero chance you can guess my number! 

nc offsec-chalbroker.osiris.cyber.nyu.edu 1514
```
Running the binary:

```aiignore
./pseudo_rand
Can you guess my number?
```
Going to binja...

This one appears to be a pseudo random number generator synchronization problem like the previous challenge. Here, however, the seed is the current time plus 25, and the binary would like the next random number returned.

The binary will take in a string of characters and convert them to an integer do to the comparison. I'll start by copying the last solver script and making my changes.

And the results are:

```aiignore
I guess it wasn't that random!
        Here's your flag, friend: flag{l00ks_l1k3_th4t_seed_w4snt_gr34t!_3d572178edad2985}
```

