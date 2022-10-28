using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;
using Newtonsoft;
using SimpleTLSTunnelServer;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Net;
using System.Collections.Concurrent;

object tlock = new object();
object ttlock = new object();
ConcurrentQueue<TcpClient> backConnects = new ConcurrentQueue<TcpClient>();
var stableTunnelsCount = 0;
var maxStableTunnelsCount = 4;
ConcurrentQueue<TunnelSession> senderqueue = new ConcurrentQueue<TunnelSession>();
ConcurrentQueue<TunnelSession> nexthopqueue = new ConcurrentQueue<TunnelSession>();
Dictionary<string, Dictionary<ulong, Dictionary<ulong, Packet>>> responsesDict = new Dictionary<string, Dictionary<ulong, Dictionary<ulong, Packet>>>();
Dictionary<string, Dictionary<ulong, SocksSession>> connections = new Dictionary<string, Dictionary<ulong, SocksSession>>();
TTunnelServerConfig config = null;
if (!File.Exists("config.json"))
{
    config = new TTunnelServerConfig();
    File.WriteAllText("config.json", JsonConvert.SerializeObject(config));
}
else
{
    config = JsonConvert.DeserializeObject<TTunnelServerConfig>(File.ReadAllText("config.json"));
    maxStableTunnelsCount = config.stable_tunnels;
}

int connectionsRequired = 0;
var cert = new X509Certificate("cert.pfx");
void StableTunnelHandler(TcpClient client)
{
    string endpoint = "";
    try
    {
        var tunnelsw = new Stopwatch();
        tunnelsw.Start();
        bool lastserver = false;
        var sw = new Stopwatch();
        sw.Start();
        NetworkStream tcptunnel = client.GetStream();
        client.ReceiveTimeout = 30000;
        client.SendTimeout = 30000;
        var disabled = false;
        endpoint = tcptunnel.Socket.RemoteEndPoint.ToString();
        var IP = Convert.ToHexString(SHA1.HashData(Encoding.ASCII.GetBytes(endpoint.Substring(0, endpoint.IndexOf(':')))));
        SslStream encryptedStream = new SslStream(tcptunnel, true, userCertificateValidationCallback, userCertificateSelectionCallback);
        if (!endpoint.Contains(config.nextHop_address))
        {
            encryptedStream.AuthenticateAsServer(cert, false, false);
        }
        else/* if ((!config.BackConnectCapability && config.nextHop_address != "127.0.0.1") || (config.BackConnectCapability && endpoint.Contains(config.nextHop_address)))*/
        {
            encryptedStream.AuthenticateAsClient("", null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
        }
        if (config.nextHop_address == "127.0.0.1")
            lastserver = true;
        else
            lastserver = false;
        Console.WriteLine(String.Format("Stable Tunnel Connection From: {0}", endpoint));
        encryptedStream.WriteByte(0x00);
        while (true)
        {
            try
            {
                if (!client.Connected || sw.ElapsedMilliseconds > 30000 || (disabled && tunnelsw.ElapsedMilliseconds > 5000))
                    break;
                if (tcptunnel.DataAvailable)
                {
                    lock (ttlock)
                    {
                        if (senderqueue.Count > 0 && (DateTime.Now - senderqueue.FirstOrDefault().ts).TotalSeconds > 30)
                        {
                            TunnelSession tunnelSession = null;
                            senderqueue.TryDequeue(out tunnelSession);
                        }

                        if (nexthopqueue.Count > 0 && (DateTime.Now - nexthopqueue.FirstOrDefault().ts).TotalSeconds > 30)
                        {
                            TunnelSession tunnelSession = null;
                            nexthopqueue.TryDequeue(out tunnelSession);
                        }
                    }
                    sw.Restart();
                    var type = encryptedStream.ReadByte();
                    if (type == 0x02)
                    {
                        var sessionidbytes = new byte[8];
                        var lengthbytes = new byte[4];
                        var orderbytes = new byte[8];
                        var iplengthbytes = new byte[4];
                        encryptedStream.Read(iplengthbytes);
                        var iplength = BitConverter.ToInt32(iplengthbytes);
                        var ipbytes = new byte[iplength];
                        encryptedStream.Read(ipbytes);
                        var ip = Encoding.ASCII.GetString(ipbytes);
                        encryptedStream.Read(sessionidbytes);
                        var sessionid = BitConverter.ToUInt64(sessionidbytes);
                        encryptedStream.Read(orderbytes);
                        var order = BitConverter.ToUInt64(orderbytes);

                        if (ip == "")
                            ip = IP;
                        if (!ip.Contains(IP))
                        {
                            ip += ":" + IP;
                        }

                        encryptedStream.Read(lengthbytes);
                        var length = BitConverter.ToInt32(lengthbytes);
                        var buffer = new byte[65536];
                        var data = new List<byte>();
                        var totalread = 0;
                        while (totalread < length)
                        {
                            var read = encryptedStream.Read(buffer, 0, length - totalread > buffer.Length ? buffer.Length : length - totalread);
                            data.AddRange(buffer.Take(read));
                            totalread += read;
                        }
                        if (lastserver)
                        {
                            lock (ttlock)
                            {
                                if (!responsesDict.ContainsKey(ip))
                                {
                                    responsesDict.Add(ip, new Dictionary<ulong, Dictionary<ulong, Packet>>());
                                    new Thread(() =>
                                    {
                                        ClientHandler(ip);
                                    }).Start();
                                }
                                if (!responsesDict[ip].ContainsKey(sessionid))
                                {
                                    responsesDict[ip].Add(sessionid, new Dictionary<ulong, Packet>());
                                }
                                responsesDict[ip][sessionid].Add(order, new Packet() { data = data.ToArray(), ts = DateTime.Now });
                            }
                        }
                        //else if (!tonext && !lastserver)
                        //{
                        //        lock (ttlock)
                        //        {
                        //            if (!responsesDict.ContainsKey(sessionid))
                        //            {
                        //                responsesDict.Add(sessionid, new Dictionary<ulong, byte[]>());
                        //            }
                        //        responsesDict[sessionid].Add(order, data.ToArray());
                        //        }
                        //}
                        else
                        {
                            if (!responsesDict.ContainsKey(ip))
                            {
                                responsesDict.Add(ip, new Dictionary<ulong, Dictionary<ulong, Packet>>());
                            }
                            if (endpoint.Contains(config.nextHop_address))
                                senderqueue.Enqueue(new TunnelSession() { Data = data.ToArray(), ID = sessionid, order = order, IP = ip, ts = DateTime.Now });
                            else
                                nexthopqueue.Enqueue(new TunnelSession() { Data = data.ToArray(), ID = sessionid, order = order, IP = ip, ts = DateTime.Now });
                        }
                        data.Clear();
                    }
                    else if (type == 0x03)
                    {
                        var sessionidbytes = new byte[8];
                        var iplengthbytes = new byte[4];
                        encryptedStream.Read(iplengthbytes);
                        var iplength = BitConverter.ToInt32(iplengthbytes);
                        var ipbytes = new byte[iplength];
                        encryptedStream.Read(ipbytes);
                        var ip = Encoding.ASCII.GetString(ipbytes);
                        encryptedStream.Read(sessionidbytes);
                        var sessionid = BitConverter.ToUInt64(sessionidbytes);
                        if (ip == "")
                            ip = IP;
                        if (!ip.Contains(IP))
                        {
                            ip += ":" + IP;
                        }
                        if (!lastserver)
                        {
                            nexthopqueue.Enqueue(new TunnelSession() { ID = sessionid, IP = ip, ts = DateTime.Now, close = true });
                        }
                        try
                        {
                            responsesDict[ip].Remove(sessionid);
                        }
                        catch
                        {

                        }
                    }
                    else if (type == 0x04)
                    {
                        var sessionidbytes = new byte[8];
                        var iplengthbytes = new byte[4];
                        var orderbytes = new byte[8];
                        encryptedStream.Read(iplengthbytes);
                        var iplength = BitConverter.ToInt32(iplengthbytes);
                        var ipbytes = new byte[iplength];
                        encryptedStream.Read(ipbytes);
                        var ip = Encoding.ASCII.GetString(ipbytes);
                        encryptedStream.Read(sessionidbytes);
                        var sessionid = BitConverter.ToUInt64(sessionidbytes);
                        encryptedStream.Read(orderbytes);
                        var order = BitConverter.ToUInt64(orderbytes);
                        if (ip == "")
                            ip = IP;
                        if (!ip.Contains(IP))
                        {
                            ip += ":" + IP;
                        }
                        if (!lastserver)
                        {
                            if (endpoint.Contains(config.nextHop_address))
                                senderqueue.Enqueue(new TunnelSession() { ID = sessionid, IP = ip, ts = DateTime.Now, ack = true, order = order });
                            else
                                nexthopqueue.Enqueue(new TunnelSession() { ID = sessionid, IP = ip, ts = DateTime.Now, ack = true, order = order });
                        }
                        else
                        {
                            responsesDict[ip][sessionid].Add(order, new Packet() { data = new byte[] { 0x04 }, ts = DateTime.Now });
                        }
                    }
                    else if (type == 0x11)
                    {
                        tunnelsw.Restart();
                        disabled = true;
                    }
                }
                lock (ttlock)
                {
                    if (nexthopqueue.Count > 0 && endpoint.Contains(config.nextHop_address) && !disabled)
                    {
                        sw.Restart();
                        TunnelSession tunnelSession = null;
                        nexthopqueue.TryDequeue(out tunnelSession);
                        var ipbytes = Encoding.ASCII.GetBytes(tunnelSession.IP);
                        var iplengthbytes = BitConverter.GetBytes(tunnelSession.IP.Length);
                        var sessionidbytes = BitConverter.GetBytes(tunnelSession.ID);
                        if (tunnelSession.close)
                        {
                            var data = new List<byte>();
                            data.Add(0x03);
                            data.AddRange(iplengthbytes);
                            data.AddRange(ipbytes);
                            data.AddRange(sessionidbytes);
                            encryptedStream.Write(data.ToArray());
                            encryptedStream.Flush();
                            data.Clear();
                        }
                        else if (tunnelSession.ack)
                        {
                            var orderbytes = BitConverter.GetBytes(tunnelSession.order);
                            var data = new List<byte>();
                            data.Add(0x04);
                            data.AddRange(iplengthbytes);
                            data.AddRange(ipbytes);
                            data.AddRange(sessionidbytes);
                            data.AddRange(orderbytes);
                            encryptedStream.Write(data.ToArray());
                            encryptedStream.Flush();
                            data.Clear();
                        }
                        else
                        {
                            var orderbytes = BitConverter.GetBytes(tunnelSession.order);
                            var lengthbytes = BitConverter.GetBytes(tunnelSession.Data.Length);
                            var data = new List<byte>();
                            data.Add(0x02);
                            data.AddRange(iplengthbytes);
                            data.AddRange(ipbytes);
                            data.AddRange(sessionidbytes);
                            data.AddRange(orderbytes);
                            data.AddRange(lengthbytes);
                            data.AddRange(tunnelSession.Data);
                            encryptedStream.Write(data.ToArray());
                            encryptedStream.Flush();
                            data.Clear();
                        }
                    }
                }
                lock (ttlock)
                {
                    if (senderqueue.Count > 0 && senderqueue.FirstOrDefault().IP.Contains(IP) && !endpoint.Contains(config.nextHop_address) && !disabled)
                    {
                        sw.Restart();
                        TunnelSession tunnelSession = null;
                        senderqueue.TryDequeue(out tunnelSession);
                        var sessionidbytes = BitConverter.GetBytes(tunnelSession.ID);
                        var ipbytes = Encoding.ASCII.GetBytes(tunnelSession.IP);
                        var iplengthbytes = BitConverter.GetBytes(tunnelSession.IP.Length);
                        if (tunnelSession.close)
                        {
                            var data = new List<byte>();
                            data.Add(0x03);
                            data.AddRange(sessionidbytes);
                            data.AddRange(iplengthbytes);
                            data.AddRange(ipbytes);
                            encryptedStream.Write(data.ToArray());
                            encryptedStream.Flush();
                            data.Clear();
                        }
                        else if (tunnelSession.ack)
                        {
                            var orderbytes = BitConverter.GetBytes(tunnelSession.order);
                            var data = new List<byte>();
                            data.Add(0x04);
                            data.AddRange(iplengthbytes);
                            data.AddRange(ipbytes);
                            data.AddRange(sessionidbytes);
                            data.AddRange(orderbytes);
                            encryptedStream.Write(data.ToArray());
                            encryptedStream.Flush();
                            data.Clear();
                        }
                        else
                        {
                            var orderbytes = BitConverter.GetBytes(tunnelSession.order);
                            var lengthbytes = BitConverter.GetBytes(tunnelSession.Data.Length);
                            var data = new List<byte>();
                            data.Add(0x02);
                            data.AddRange(iplengthbytes);
                            data.AddRange(ipbytes);
                            data.AddRange(sessionidbytes);
                            data.AddRange(orderbytes);
                            data.AddRange(lengthbytes);
                            data.AddRange(tunnelSession.Data);
                            encryptedStream.Write(data.ToArray());
                            encryptedStream.Flush();
                            data.Clear();
                        }
                    }
                }
                if (sw.ElapsedMilliseconds > 1000)
                {
                    sw.Restart();
                    encryptedStream.Write(new byte[] { 0x10 });
                    encryptedStream.Flush();
                }
                //if (!tcptunnel.DataAvailable || senderqueue.Count == 0 || nexthopqueue.Count == 0)
                //{
                Thread.Sleep(1);
                //}
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.StackTrace);
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.StackTrace);
    }
    if (endpoint.Contains(config.nextHop_address))
        stableTunnelsCount--;
    Console.WriteLine(String.Format("Dropped Stable Tunnel Connection From: {0}", endpoint));
}
void ClientHandler(string IP = "")
{
    string endpoint = "";
    bool encryptfornext = false;
    try
    {
        var buffer = new List<byte>();
        //NetworkStream clientstream = client.GetStream();
        //endpoint = clientstream.Socket.RemoteEndPoint.ToString();

        //var sslStream = new SslStream(clientstream, true, userCertificateValidationCallback);
        //sslStream.AuthenticateAsServer(cert, false, false);
        //Console.WriteLine(String.Format("Incoming Connection From: {0}", IP));
        //if (config.BackConnectCapability && config.BackConnect_address == "127.0.0.1")
        //{
        //    lock (tlock)
        //    {
        //        connectionsRequired++;
        //    }
        //    int counter = 0;
        //    while (nextConnection == null)
        //    {
        //        if (backConnects.Count > 0)
        //            backConnects.TryDequeue(out nextConnection);
        //        Thread.Sleep(1);
        //        counter++;
        //        if (counter >= 2000)
        //            return;
        //    }
        //    hopStream = nextConnection.GetStream();
        //}
        //else
        //{
        //nextConnection = new TcpClient(config.nextHop_address, config.nextHop_port);
        //}
        //if (config.nextHop_address != "" && config.nextHop_address != "127.0.0.1")
        //{
        //    hopStream = new SslStream(nextConnection.GetStream(), true, userCertificateValidationCallback);
        //    ((SslStream)hopStream).AuthenticateAsClient("", null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
        //}
        if (!connections.ContainsKey(IP))
        {
            connections.Add(IP, new Dictionary<ulong, SocksSession>());
        }
        var sw = new Stopwatch();
        sw.Start();
        while (true)
        {
            try
            {
                if (sw.ElapsedMilliseconds > 30000)
                    break;
                var read = 0;
                foreach (var response in responsesDict[IP])
                {
                    var currentID = response.Key;
                    var packets = response.Value;
                    if (!responsesDict[IP].ContainsKey(currentID))
                    {
                        connections[IP].Remove(currentID);
                        break;
                    }
                    if (!connections[IP].ContainsKey(currentID))
                    {
                        connections[IP].Add(currentID, new SocksSession() { client = new TcpClient(config.nextHop_address, config.nextHop_port) });
                    }
                    var hopStream = connections[IP][currentID].client.GetStream();
                    lock (ttlock)
                    {
                        if (responsesDict[IP][currentID].ContainsKey(connections[IP][currentID].expectedack))
                        {
                            responsesDict[IP][currentID].Remove(connections[IP][currentID].expectedack);
                            connections[IP][currentID].expectedack = 0;
                            connections[IP][currentID].packetsforack = 0;
                        }
                        while (packets.Count > 0 && responsesDict[IP][currentID].ContainsKey(connections[IP][currentID].readorder))
                        {
                            sw.Restart();
                            //var bbbb = new byte[65536];
                            //do
                            //{
                            //    read = sslStream.Read(bbbb, 0, bbbb.Length);
                            //    buffer.AddRange(bbbb.Take(read));
                            //}
                            //while (clientstream.DataAvailable && read != 0);
                            //Console.Write(Encoding.ASCII.GetString(buffer.ToArray()));
                            byte[] data = responsesDict[IP][currentID][connections[IP][currentID].readorder].data;
                            senderqueue.Enqueue(new TunnelSession() { ID = currentID, Data = new byte[] { 0x04 }, order = connections[IP][currentID].readorder, IP = IP, ts = DateTime.Now, ack = true });
                            hopStream.Write(data);
                            hopStream.Flush();
                            responsesDict[IP][currentID].Remove(connections[IP][currentID].readorder);
                            connections[IP][currentID].readorder += 2;
                            //buffer.Clear();
                        }
                    }
                    while (hopStream.DataAvailable && connections[IP][currentID].expectedack == 0)
                    {
                        while (hopStream.DataAvailable && buffer.Count < 65536)
                        {
                            var bbbb = new byte[65536];
                            //do
                            //{
                            read = hopStream.Read(bbbb, 0, bbbb.Length);
                            buffer.AddRange(bbbb.Take(read));
                        }
                        //} while (nextConnection.Available > 0 && read != 0);
                        //sslStream.Write(buffer.ToArray());
                        senderqueue.Enqueue(new TunnelSession() { ID = currentID, Data = buffer.ToArray(), order = connections[IP][currentID].writeorder, IP = IP, ts = DateTime.Now });
                        //if ((buffer.Count >= 65536 && connections[IP][currentID].packetsforack >= 10) && (buffer.Count <= 0 && connections[IP][currentID].packetsforack >= 3))
                        {
                            connections[IP][currentID].expectedack = connections[IP][currentID].writeorder;
                        }
                        connections[IP][currentID].packetsforack++;
                        connections[IP][currentID].writeorder += 2;
                        buffer.Clear();
                    }
                }
                if (read == 0)
                    Thread.Sleep(1);
            }
            catch (Exception ex)
            {
            }

        }
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.StackTrace);
    }
    responsesDict.Remove(IP);
    connections.Remove(IP);
    //Console.WriteLine(String.Format("Dropped Connection From: {0}", IP));
}
void BackConnectHandler(TcpClient client)
{
    string endpoint = "";
    try
    {
        var sw = new Stopwatch();
        sw.Start();
        NetworkStream clientstream = client.GetStream();
        endpoint = clientstream.Socket.RemoteEndPoint.ToString();

        var sslStream = new SslStream(clientstream, true, userCertificateValidationCallback);
        sslStream.AuthenticateAsServer(cert, false, false);
        Console.WriteLine(String.Format("Incoming BackConnect From: {0}", endpoint));
        while (true)
        {
            try
            {
                if (!client.Connected || sw.ElapsedMilliseconds >= 1500)
                    break;
                var read = 0;
                if (clientstream.DataAvailable)
                {
                    sw.Restart();
                    do
                    {
                        read = sslStream.ReadByte();
                    }
                    while (clientstream.DataAvailable && read != -1);
                }
                while (stableTunnelsCount < maxStableTunnelsCount)
                {
                    sslStream.Write(new byte[] { 0x01 });
                    sslStream.Flush();
                    lock (tlock)
                    {
                        stableTunnelsCount++;
                    }
                }
                if (sw.ElapsedMilliseconds > 1000)
                {
                    sw.Restart();
                    sslStream.Write(new byte[] { 0x10 });
                    sslStream.Flush();
                }
                if (read == 0)
                {
                    Thread.Sleep(1);
                }
            }
            catch
            {

            }

        }
        client.Close();
    }
    catch
    {

    }
    Console.WriteLine(String.Format("Dropped BackConnect From: {0}", endpoint));
}
void BackConnectServerHandler(TcpClient client)
{
    SslStream sslStream = null;
    string endpoint = "";
    try
    {
        var sw = new Stopwatch();
        sw.Start();
        NetworkStream clientstream = client.GetStream();
        sslStream = new SslStream(clientstream, true, userCertificateValidationCallback);
        sslStream.AuthenticateAsClient("", null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
        endpoint = clientstream.Socket.RemoteEndPoint.ToString();
        Console.WriteLine(String.Format("Outgoing BackConnect To: {0}", endpoint));
        while (true)
        {
            try
            {
                var read = 0;
                if (clientstream.DataAvailable)
                {
                    sw.Restart();
                    do
                    {
                        read = sslStream.ReadByte();
                        if (read == 0x01)
                        {
                            Console.WriteLine("New Connection Requested");
                            var tcpclient = new TcpClient(config.BackConnect_address, config.BackConnect_port);
                            new Thread(() =>
                            {
                                StableTunnelHandler(tcpclient);
                            }).Start();
                        }
                        else if (read == 0x10)
                        {
                            //Console.WriteLine("Keep Alive");
                        }
                    }
                    while (clientstream.DataAvailable && read != -1);
                }
                if (read == 0)
                {
                    Thread.Sleep(1);
                }
                if (!client.Connected || sw.ElapsedMilliseconds >= 1500)
                    break;
            }
            catch
            {

            }

        }
        client.Close();
    }
    catch
    {

    }
    Console.WriteLine(String.Format("Outgoing BackConnect To: {0}", endpoint));
}

X509Certificate userCertificateSelectionCallback(object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate? remoteCertificate, string[] acceptableIssuers)
{
    return cert as X509Certificate;
}

bool userCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
{
    return true;
}

var tcplistener = new TcpListener(System.Net.IPAddress.Any, config.ListeningPort);
tcplistener.Start();
Socks5.Servers.SimpleSocks5Server socksServer = null;
ValueTask? sockstask = null;
if (config.nextHop_address == "127.0.0.1")
{
    socksServer = new Socks5.Servers.SimpleSocks5Server(new System.Net.IPEndPoint(System.Net.IPAddress.Any, config.nextHop_port));
    sockstask = socksServer.StartAsync();
}
TcpListener backtcplistener = null;
TcpClient backtcpclient = null;
if (config.BackConnectCapability && config.BackConnect_address == "127.0.0.1")
{
    backtcplistener = new TcpListener(System.Net.IPAddress.Any, config.BackConnectManager_port);
    backtcplistener.Start();
}

while (true)
{
    if (socksServer != null && (sockstask.Value.IsFaulted || sockstask.Value.IsCanceled))
    {
        sockstask = socksServer.StartAsync();
    }
    if (tcplistener.Pending())
    {
        var client = tcplistener.AcceptTcpClient();
        new Thread(() =>
        {
            StableTunnelHandler(client);
        }).Start();
    }
    if (config.nextHop_address != "127.0.0.1" && !config.BackConnectCapability && stableTunnelsCount < maxStableTunnelsCount)
    {
        try
        {
            stableTunnelsCount++;
            var client = new TcpClient(config.nextHop_address, config.nextHop_port);
            new Thread(() =>
            {
                StableTunnelHandler(client);
            }).Start();
        }
        catch
        {

        }
    }
    if (backtcplistener != null && backtcplistener.Pending())
    {
        new Thread(() =>
        {
            BackConnectHandler(backtcplistener.AcceptTcpClient());
        }).Start();
    }
    if (config.BackConnectCapability && config.BackConnect_address != "127.0.0.1" && (backtcpclient == null || !backtcpclient.Connected))
    {
        try
        {
            backtcpclient = new TcpClient(config.BackConnect_address, config.BackConnectManager_port);
            new Thread(() =>
            {
                BackConnectServerHandler(backtcpclient);
            }).Start();
        }
        catch
        {
            Console.WriteLine(String.Format("BackConnect Failed!"));
        }
    }
    GC.Collect();
    Thread.Sleep(100);
}