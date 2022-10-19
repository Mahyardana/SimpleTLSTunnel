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
var maxStableTunnelsCount = 16;
ConcurrentQueue<TunnelSession> senderqueue = new ConcurrentQueue<TunnelSession>();
ConcurrentQueue<TunnelSession> nexthopqueue = new ConcurrentQueue<TunnelSession>();
Dictionary<string, Dictionary<ulong, Dictionary<ulong, byte[]>>> responsesDict = new Dictionary<string, Dictionary<ulong, Dictionary<ulong, byte[]>>>();
TTunnelServerConfig config = null;
if (!File.Exists("config.json"))
{
    config = new TTunnelServerConfig();
    File.WriteAllText("config.json", JsonConvert.SerializeObject(config));
}
else
{
    config = JsonConvert.DeserializeObject<TTunnelServerConfig>(File.ReadAllText("config.json"));
}

int connectionsRequired = 0;
var cert = new X509Certificate("cert.pfx");
void StableTunnelHandler(TcpClient client)
{
    string endpoint = "";
    try
    {
        bool tonext = false;
        bool lastserver = false;
        var sw = new Stopwatch();
        sw.Start();
        NetworkStream tcptunnel = client.GetStream();
        endpoint = tcptunnel.Socket.RemoteEndPoint.ToString();
        var IP = endpoint.Substring(0, endpoint.IndexOf(':'));
        if (!responsesDict.ContainsKey(IP))
            responsesDict.Add(IP, new Dictionary<ulong, Dictionary<ulong, byte[]>>());
        SslStream encryptedStream = new SslStream(tcptunnel, true, userCertificateValidationCallback, userCertificateSelectionCallback);
        if (!endpoint.Contains(config.nextHop_address))
            encryptedStream.AuthenticateAsServer(cert, false, false);
        else if (!config.BackConnectCapability && config.nextHop_address != "127.0.0.1")
            encryptedStream.AuthenticateAsClient("", null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
        if (endpoint.Contains(config.nextHop_address))
            stableTunnelsCount++;
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
                if (!client.Connected)
                    break;
                if (tcptunnel.DataAvailable)
                {
                    sw.Restart();
                    var type = encryptedStream.ReadByte();
                    if (type == 0x02)
                    {
                        var sessionidbytes = new byte[8];
                        var lengthbytes = new byte[4];
                        var orderbytes = new byte[8];
                        var iplengthbytes = new byte[4];
                        encryptedStream.Read(sessionidbytes);
                        var sessionid = BitConverter.ToUInt64(sessionidbytes);
                        encryptedStream.Read(orderbytes);
                        var order = BitConverter.ToUInt64(orderbytes);
                        encryptedStream.Read(iplengthbytes);
                        var iplength = BitConverter.ToInt32(iplengthbytes);
                        var ipbytes = new byte[iplength];
                        encryptedStream.Read(ipbytes);
                        var ip = Encoding.ASCII.GetString(ipbytes);

                        if (ip == "")
                            ip = IP;
                        if (!responsesDict.ContainsKey(ip))
                            responsesDict.Add(ip, new Dictionary<ulong, Dictionary<ulong, byte[]>>());
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
                                if (!responsesDict[ip].ContainsKey(sessionid))
                                {
                                    responsesDict[ip].Add(sessionid, new Dictionary<ulong, byte[]>());
                                    new Thread(() =>
                                    {
                                        ClientHandler(null, sessionid, ip);
                                    }).Start();
                                }
                            }
                            responsesDict[ip][sessionid].Add(order, data.ToArray());
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
                            //Console.WriteLine(ip);
                            if (IP == config.nextHop_address)
                                senderqueue.Enqueue(new TunnelSession() { Data = data.ToArray(), ID = sessionid, order = order, IP = ip });
                            else
                                nexthopqueue.Enqueue(new TunnelSession() { Data = data.ToArray(), ID = sessionid, order = order, IP = ip });
                        }
                        data.Clear();
                    }
                }
                lock (ttlock)
                {
                    if (nexthopqueue.Count > 0 && IP == config.nextHop_address)
                    {
                        sw.Restart();
                        TunnelSession tunnelSession;
                        nexthopqueue.TryDequeue(out tunnelSession);
                        var sessionidbytes = BitConverter.GetBytes(tunnelSession.ID);
                        var ipbytes = Encoding.ASCII.GetBytes(tunnelSession.IP);
                        var iplengthbytes = BitConverter.GetBytes(tunnelSession.IP.Length);
                        var orderbytes = BitConverter.GetBytes(tunnelSession.order);
                        var lengthbytes = BitConverter.GetBytes(tunnelSession.Data.Length);
                        var data = new List<byte>();
                        data.Add(0x02);
                        data.AddRange(sessionidbytes);
                        data.AddRange(orderbytes);
                        data.AddRange(iplengthbytes);
                        data.AddRange(ipbytes);
                        data.AddRange(lengthbytes);
                        data.AddRange(tunnelSession.Data);
                        encryptedStream.Write(data.ToArray());
                        encryptedStream.Flush();
                        data.Clear();
                    }
                    if (senderqueue.Count > 0 && (senderqueue.FirstOrDefault().IP == IP || lastserver))
                    {
                        sw.Restart();
                        TunnelSession tunnelSession;
                        senderqueue.TryDequeue(out tunnelSession);
                        var sessionidbytes = BitConverter.GetBytes(tunnelSession.ID);
                        var orderbytes = BitConverter.GetBytes(tunnelSession.order);
                        var lengthbytes = BitConverter.GetBytes(tunnelSession.Data.Length);
                        var ipbytes = Encoding.ASCII.GetBytes(tunnelSession.IP);
                        var iplengthbytes = BitConverter.GetBytes(tunnelSession.IP.Length);
                        var data = new List<byte>();
                        data.Add(0x02);
                        data.AddRange(sessionidbytes);
                        data.AddRange(orderbytes);
                        data.AddRange(iplengthbytes);
                        data.AddRange(ipbytes);
                        data.AddRange(lengthbytes);
                        data.AddRange(tunnelSession.Data);
                        encryptedStream.Write(data.ToArray());
                        encryptedStream.Flush();
                        data.Clear();
                    }
                }
                if (sw.ElapsedMilliseconds > 1000)
                {
                    sw.Restart();
                    encryptedStream.Write(new byte[] { 0x10 });
                    encryptedStream.Flush();
                }
                if (!tcptunnel.DataAvailable || senderqueue.Count == 0 || nexthopqueue.Count == 0)
                {
                    Thread.Sleep(1);
                }
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
    stableTunnelsCount--;
    Console.WriteLine(String.Format("Dropped Stable Tunnel Connection From: {0}", endpoint));
}
void ClientHandler(TcpClient client, ulong currentID = ulong.MaxValue, string IP = "")
{
    string endpoint = "";
    bool encryptfornext = false;
    try
    {
        ulong readorder = 0;
        ulong writeorder = 0;
        var buffer = new List<byte>();
        if (client == null && currentID == ulong.MaxValue && config.BackConnectCapability)
        {
            client = new TcpClient(config.BackConnect_address, config.BackConnect_port);
            while (client.Available <= 0)
            {
                Thread.Sleep(1);
            }
        }
        //NetworkStream clientstream = client.GetStream();
        //endpoint = clientstream.Socket.RemoteEndPoint.ToString();

        //var sslStream = new SslStream(clientstream, true, userCertificateValidationCallback);
        //sslStream.AuthenticateAsServer(cert, false, false);
        Console.WriteLine(String.Format("Incoming Connection From: {0}", IP));

        TcpClient nextConnection = null;
        Stream hopStream = null;
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
        nextConnection = new TcpClient(config.nextHop_address, config.nextHop_port);
        hopStream = nextConnection.GetStream();
        //}
        //if (config.nextHop_address != "" && config.nextHop_address != "127.0.0.1")
        //{
        //    hopStream = new SslStream(nextConnection.GetStream(), true, userCertificateValidationCallback);
        //    ((SslStream)hopStream).AuthenticateAsClient("", null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
        //}
        var sw = new Stopwatch();
        sw.Start();
        while (true)
        {
            try
            {
                if (!nextConnection.Connected)
                    break;
                var read = 0;
                lock (ttlock)
                {
                    if (responsesDict[IP][currentID].Count > 0 && responsesDict[IP][currentID].ContainsKey(readorder))
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
                        byte[] data = responsesDict[IP][currentID][readorder];
                        hopStream.Write(data);
                        hopStream.Flush();
                        responsesDict[IP][currentID].Remove(readorder);
                        readorder++;
                        //buffer.Clear();
                    }
                }
                if (nextConnection.Available > 0)
                {
                    sw.Restart();
                    var bbbb = new byte[65536];
                    //do
                    //{
                    read = hopStream.Read(bbbb, 0, bbbb.Length);
                    buffer.AddRange(bbbb.Take(read));
                    //} while (nextConnection.Available > 0 && read != 0);
                    //sslStream.Write(buffer.ToArray());
                    senderqueue.Enqueue(new TunnelSession() { ID = currentID, Data = buffer.ToArray(), order = writeorder, IP = IP });
                    writeorder++;
                    buffer.Clear();
                }
                if (read == 0)
                {
                    Thread.Sleep(1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.StackTrace);
            }

        }
        nextConnection.Close();
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.StackTrace);
    }
    responsesDict[IP].Remove(currentID);
    Console.WriteLine(String.Format("Dropped Connection From: {0}", IP));
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
                while (connectionsRequired > 0)
                {
                    sslStream.Write(new byte[] { 0x01 });
                    sslStream.Flush();
                    lock (tlock)
                    {
                        connectionsRequired--;
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
                            Console.WriteLine("Keep Alive");
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
if (config.nextHop_address == "127.0.0.1")
{
    var socksServer = new Socks5.Servers.SimpleSocks5Server(new System.Net.IPEndPoint(System.Net.IPAddress.Any, config.nextHop_port));
    socksServer.StartAsync();
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
    if (tcplistener.Pending())
    {
        var client = tcplistener.AcceptTcpClient();
        if (client.Client.RemoteEndPoint.ToString().Contains(config.nextHop_address) && config.BackConnectCapability)
        {
            backConnects.Enqueue(client);
        }
        else
        {
            new Thread(() =>
            {
                StableTunnelHandler(client);
            }).Start();
        }
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