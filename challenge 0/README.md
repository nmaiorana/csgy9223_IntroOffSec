# Week 0 CTF

## Are You Alive: Server Edition 5

This is a simple challenge to get us started to use Osiris. The goal is to submit a message to the server and get a response back.
The message is will be sent using the following command line syntax:

```nc offsec-chalbroker.osiriris.cyber.nyu.edu 1237```

### Host Server Setup
I first started by launching the Ubuntu server on my Surface Pro 6. I decided to update my Ubuntu server to the latest version.

In WSL Ubuntu:

```
sudo apt update && sudo apt full-upgrade
```

In Windows:

```  
wsl -l -v
wsl --terminate Ubuntu
```

Restart Ubuntu and then:

```sudo do-release-upgrade```

### Attempt 1
For this attempt I started the VPN on my Windows machine, thinking it would transfer over to the WSL Ubuntu. I was wrong. I had to start the VPN on the Ubuntu server.
I executed the command:

```
nc offsec-chalbroker.osiriris.cyber.nyu.edu 1237
```

And the command hung. I had to CTL+C to exit.

### Attempt 2
For this attempt I installed the Open Connect VPN server on my Ubuntu server. If first had to turn off the VPN on Windows.

On Ubuntu:

```
sudo apt-get update
sudo apt-get install openconnect network-manager-openconnect network-manager-openconnect-gnome
```
I then connected to the VPN server:

```
sudo openconnect --background --user nam10102 vpnsec.nyu.edu
```

I was prompted for my password and then prompted again. For the 2nd prompt I entered "push" and Duo prompted me on my phone.

I entered the command:

```
nc offsec-chalbroker.osiriris.cyber.nyu.edu 1237
```

and was prompted by the server:

```
Please input your NetID (something like abc123):
```

I entered my NetID and was greeted with:

```
Here's your flag, friend: flag{n0w_y0u_kn0w_wh4t_t0_d0_t0_w1n!_6f07d51a7d15ab78}
```

Success!

### Attempt 3 using Python and pwntools