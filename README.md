# SimpleTLSTunnel
A Simple TLS Based Tunnle (Socks5+TLS)

## Requirements:

1. One VPS or Server as Destination of Tunneling Porcess (or Two For using Multi Hop Functionality.

2. Dotnet 6 Runtime Installed on both Client and Server

3. Generating your own X509 Certificate and getting cert.pfx (for server) and cert.crt (for client)

(You can use [THIS SITE](https://certificatetools.com))

## How To Use:

1. Build Solution Using Visual Studio 2022 or Use Release Build or Download Artifacts From Actions and Artifacts Are Always Up To Date

2. Config Server And Client To Connect To Each Other

3. Put cert.pfx in server build folder and put cert.crt in client build folder (missmatch certificates will cause tunnel to fail tls handshake)

4. Use Specified Port in client localhost to connect to socks5 server and tunnel your traffic (Default: 1080)

At last you have to make sure that you allow listener port in server firewall

## Config Examples:

Both Client And Server Use config.json file as configuration

### Single Hop Server

Client Side config.json
```
{
  "stable_tunnel": 1,
  "server_address": "SERVER_IP",
  "server_port": SERVER_LISTENER_PORT,
  "proxy_listening_port": PROXY_LISTENER_PORT
}
```
server_address is your server ip address or hostname

server_port is your server port which program uses to connect to server

proxy_listening_port is a port which program uses to get socks5 packets in client

Server Side config.json
```
{
  "stable_tunnel": 16,
  "nextHop_address": "127.0.0.1",
  "nextHop_port": 8080,
  "ListeningPort": 443,
  "BackConnectCapability": false,
  "BackConnect_address": "127.0.0.1",
  "BackConnectManager_port": 444,
  "BackConnect_port": 443
}
```
nextHop_address is set to localhost to determine server as last destination of packets

nextHop_port is ignored in case of single hop configuration

ListeningPort is your server port exposed to public to access incoming encrypted packets

backconnect capability is not used in this scenario

### Multi Hop Servers (Two For Demonstration and Without BackConnect Capability)

let's say we have to servers one as edge and one as last destination (you can have more edges or even use multiple hops)

server1 (edge) ip address and listener port is 10.10.10.1 and 443

server2 (destination) ip address and listener port is 10.10.10.2 and 443

we config client and servers like this:

Client Side config.json
```
{
  "stable_tunnel": 1,
  "server_address": "10.10.10.2",
  "server_port": 443,
  "proxy_listening_port": 1080
}
```

Server1 (Edge) config.json
```
{
  "stable_tunnel": 16,
  "nextHop_address": "10.10.10.3",
  "nextHop_port": 443,
  "ListeningPort": 443,
  "BackConnectCapability": false,
  "BackConnect_address": "127.0.0.1",
  "BackConnectManager_port": 444,
  "BackConnect_port": 443
}
```

Server2 (Destination) config.json
```
{
  "stable_tunnel": 16,
  "nextHop_address": "127.0.0.1",
  "nextHop_port": 8080,
  "ListeningPort": 443,
  "BackConnectCapability": false,
  "BackConnect_address": "127.0.0.1",
  "BackConnectManager_port": 444,
  "BackConnect_port": 443
}
```

if your hop connection between servers failed DON'T WORRY. just use BackConnect and hopefully your problem will be gone :))

### Multi Hop Servers (Two For Demonstration and With BackConnect Capability)

let's say we have to servers one as edge and one as last destination (you can have more edges or even use multiple hops)

server1 (edge) ip address and listener port is 10.10.10.1 and 443

server2 (destination) ip address and listener port is 10.10.10.2 and 443

we config client and servers like this

Client Side config.json
```
{
  "stable_tunnel": 1,
  "server_address": "10.10.10.2",
  "server_port": 443,
  "proxy_listening_port": 1080
}
```

Server1 (Edge) config.json
```
{
  "stable_tunnel": 16,
  "nextHop_address": "10.10.10.3",
  "nextHop_port": 443,
  "ListeningPort": 443,
  "BackConnectCapability": true,
  "BackConnect_address": "127.0.0.1",
  "BackConnectManager_port": 444,
  "BackConnect_port": 443
}
```

Server2 (Destination) config.json
```
{
  "stable_tunnel": 16,
  "nextHop_address": "127.0.0.1",
  "nextHop_port": 8080,
  "ListeningPort": 443,
  "BackConnectCapability": true,
  "BackConnect_address": "10.10.10.2",
  "BackConnectManager_port": 444,
  "BackConnect_port": 443
}
```

and it's done

your second server will use BackConnect to your edge server and communicate with it to establish connections between them

## Bug Reports

if you see any crashes or bugs withing my code (I know it's messy but it somehow works) feel free to open an issue and the scenario that causes the crash and I will work on it as soon as I can

## MY WORDS

you can edit this tunnel to do better like using it as port forwarding tool from your localhost to your destination server

and feel free to use it as you see fit
