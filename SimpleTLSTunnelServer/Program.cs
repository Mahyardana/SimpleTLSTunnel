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
using UniversalTunTapDriver;
#pragma warning disable CS8603
#pragma warning disable CS8602
#pragma warning disable CS8600
ThreadPool.SetMaxThreads(1000, 1000);
//object tlock = new object();
object ttlock = new object();
var ipassigner = new IPAssigner(IPAddress.Parse("10.10.1.2"), IPAddress.Parse("10.10.2.255"));
ConcurrentQueue<TcpClient> backConnects = new ConcurrentQueue<TcpClient>();
var assignedIPs = new Dictionary<string, IPAddress>();
var stableTunnelsCount = 0;
var maxStableTunnelsCount = 4;
ConcurrentQueue<TunnelSession> senderqueue = new ConcurrentQueue<TunnelSession>();
ConcurrentQueue<TunnelSession> nexthopqueue = new ConcurrentQueue<TunnelSession>();
Dictionary<ulong, Dictionary<ulong, Packet>> responsesDict = new Dictionary<ulong, Dictionary<ulong, Packet>>();
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
        var keepalivesw = new Stopwatch();
        keepalivesw.Start();
        bool lastserver = false;
        var sw = new Stopwatch();
        sw.Start();
        NetworkStream tcptunnel = client.GetStream();
        client.ReceiveTimeout = 10000;
        client.SendTimeout = 10000;
        endpoint = tcptunnel.Socket.RemoteEndPoint.ToString();
        var IP = Convert.ToHexString(SHA1.HashData(Encoding.ASCII.GetBytes(endpoint.Substring(0, endpoint.IndexOf(':')))));
        //var tcpbytes = new byte[64];
        //tcptunnel.Read(tcpbytes, 0, tcpbytes.Length);
        //Console.WriteLine(Convert.ToHexString(tcpbytes));
        SslStream encryptedStream = new SslStream(tcptunnel, true, userCertificateValidationCallback, userCertificateSelectionCallback);
        if (!endpoint.Contains(config.nextHop_address))
        {
            //Console.WriteLine("server " + endpoint);
            encryptedStream.AuthenticateAsServer(cert, false, false);
        }
        else/* if ((!config.BackConnectCapability && config.nextHop_address != "127.0.0.1") || (config.BackConnectCapability && endpoint.Contains(config.nextHop_address)))*/
        {
            //Console.WriteLine("client");
            encryptedStream.AuthenticateAsClient("", null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
        }
        if (config.nextHop_address == "127.0.0.1")
            lastserver = true;
        else
            lastserver = false;
        Console.WriteLine(String.Format("Stable Tunnel Connection From: {0}", endpoint));
        encryptedStream.WriteByte(0x00);
        lock (ttlock)
        {
            //Assign IP
            {
                var data = new List<byte>();
                data.Add(0x20);
                IPAddress assignedip = null;
                if (!assignedIPs.ContainsKey(IP))
                {
                    assignedip = ipassigner.GetNewIP();
                    assignedIPs.Add(IP, assignedip);
                }
                else
                    assignedip = assignedIPs[IP];
                data.AddRange(assignedip.GetAddressBytes());
                encryptedStream.Write(data.ToArray());
                data.Clear();
            }
        }

        byte[] towrite = null;
        while (true)
        {
            try
            {
                if (!client.Connected || sw.ElapsedMilliseconds > 30000)
                    break;
                if (towrite != null)
                {
                    encryptedStream.Write(towrite);
                    encryptedStream.Flush();
                }
                lock (ttlock)
                {
                    while (senderqueue.Count > 0 && (DateTime.Now - senderqueue.FirstOrDefault().ts).TotalSeconds > 30)
                    {
                        TunnelSession tunnelSession = null;
                        senderqueue.TryDequeue(out tunnelSession);
                    }

                    while (nexthopqueue.Count > 0 && (DateTime.Now - nexthopqueue.FirstOrDefault().ts).TotalSeconds > 30)
                    {
                        TunnelSession tunnelSession = null;
                        nexthopqueue.TryDequeue(out tunnelSession);
                    }
                }
                if (tcptunnel.DataAvailable)
                {
                    sw.Restart();
                    var type = encryptedStream.ReadByte();
                    if (type == 0x02)
                    {
                        //Console.WriteLine("packet");
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
                        ip = "";

                        //Console.WriteLine("incoming: " + ip);
                        //if (!responsesDict.ContainsKey(ip))
                        //    responsesDict.Add(ip, new Dictionary<ulong, Dictionary<ulong, Packet>>());
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
                                if (!responsesDict.ContainsKey(sessionid))
                                {
                                    try
                                    {
                                        responsesDict.Add(sessionid, new Dictionary<ulong, Packet>());
                                        new Thread(() =>
                                        {
                                            ClientHandler(null, 0, "");
                                        }).Start();
                                    }
                                    catch
                                    {

                                    }
                                }
                                try
                                {
                                    responsesDict[sessionid].Add(order, new Packet() { data = data.ToArray(), ts = DateTime.Now });
                                }
                                catch
                                {

                                }
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
                            //Console.WriteLine(ip);
                            if (endpoint.Contains(config.nextHop_address))
                                lock (ttlock)
                                    senderqueue.Enqueue(new TunnelSession() { Data = data.ToArray(), ID = sessionid, order = order, IP = ip, ts = DateTime.Now });
                            else
                                lock (ttlock)
                                    nexthopqueue.Enqueue(new TunnelSession() { Data = data.ToArray(), ID = sessionid, order = order, IP = ip, ts = DateTime.Now });
                        }
                        data.Clear();
                    }
                    else if (type == 0x03)
                    {
                        //Console.WriteLine("drop");
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
                            lock (ttlock)
                                nexthopqueue.Enqueue(new TunnelSession() { ID = sessionid, IP = ip, ts = DateTime.Now, close = true });
                        }
                        try
                        {
                            lock (ttlock)
                            {
                                for (int i = 0; i < senderqueue.Count; i++)
                                {
                                    TunnelSession tunnelSession = null;
                                    senderqueue.TryDequeue(out tunnelSession);
                                    if (tunnelSession.IP != ip || tunnelSession.ID != sessionid)
                                    {
                                        senderqueue.Enqueue(tunnelSession);
                                    }
                                }

                                for (int i = 0; i < nexthopqueue.Count; i++)
                                {
                                    TunnelSession tunnelSession = null;
                                    nexthopqueue.TryDequeue(out tunnelSession);
                                    if (tunnelSession.IP != ip || tunnelSession.ID != sessionid)
                                    {
                                        nexthopqueue.Enqueue(tunnelSession);
                                    }
                                }
                                try
                                {
                                    responsesDict.Remove(sessionid);
                                }
                                catch
                                {

                                }
                            }
                        }
                        catch
                        {

                        }
                    }
                    else if (type == 0x04)
                    {
                        //Console.WriteLine("ack");
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
                            lock (ttlock)
                                nexthopqueue.Enqueue(new TunnelSession() { ID = sessionid, IP = ip, ts = DateTime.Now, ack = true, order = order });
                        }
                        else
                        {
                            try
                            {
                                lock (ttlock)
                                    responsesDict[sessionid].Add(order, new Packet() { data = new byte[] { 0x04 }, ts = DateTime.Now });
                            }
                            catch
                            {

                            }
                        }
                    }
                    else if (type == 0x10)
                    {
                        Console.WriteLine("Keep-Alive");
                    }
                }
                towrite = null;
                lock (ttlock)
                {
                    if (nexthopqueue.Count > 0 && endpoint.Contains(config.nextHop_address))
                    {
                        TunnelSession tunnelSession = null;
                        nexthopqueue.TryDequeue(out tunnelSession);
                        var ipbytes = Encoding.ASCII.GetBytes(tunnelSession.IP);
                        var iplengthbytes = BitConverter.GetBytes(tunnelSession.IP.Length);
                        var sessionidbytes = BitConverter.GetBytes(tunnelSession.ID);
                        if (tunnelSession.close)
                        {
                            //Console.WriteLine("outgoing nexthop: " + tunnelSession.IP);
                            var data = new List<byte>();
                            data.Add(0x03);
                            data.AddRange(iplengthbytes);
                            data.AddRange(ipbytes);
                            data.AddRange(sessionidbytes);
                            towrite = data.ToArray();
                            data.Clear();
                        }
                        else if (tunnelSession.ack)
                        {
                            //Console.WriteLine("outgoing nexthop: " + tunnelSession.IP);
                            var orderbytes = BitConverter.GetBytes(tunnelSession.order);
                            var data = new List<byte>();
                            data.Add(0x04);
                            data.AddRange(iplengthbytes);
                            data.AddRange(ipbytes);
                            data.AddRange(sessionidbytes);
                            data.AddRange(orderbytes);
                            towrite = data.ToArray();
                            data.Clear();
                        }
                        else
                        {
                            var orderbytes = BitConverter.GetBytes(tunnelSession.order);
                            var lengthbytes = BitConverter.GetBytes(tunnelSession.Data.Length);

                            //Console.WriteLine("outgoing nexthop: " + tunnelSession.IP);
                            var data = new List<byte>();
                            data.Add(0x02);
                            data.AddRange(iplengthbytes);
                            data.AddRange(ipbytes);
                            data.AddRange(sessionidbytes);
                            data.AddRange(orderbytes);
                            data.AddRange(lengthbytes);
                            data.AddRange(tunnelSession.Data);
                            towrite = data.ToArray();
                            data.Clear();
                        }
                    }
                }
                if (towrite != null)
                {
                    encryptedStream.Write(towrite);
                    encryptedStream.Flush();
                }
                towrite = null;
                lock (ttlock)
                {
                    if (senderqueue.Count > 0 && senderqueue.FirstOrDefault().IP.Contains(IP) && !endpoint.Contains(config.nextHop_address))
                    {
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
                            towrite = data.ToArray();
                            data.Clear();
                        }
                        else if (tunnelSession.ack)
                        {
                            var orderbytes = BitConverter.GetBytes(tunnelSession.order);
                            //Console.WriteLine("outgoing nexthop: " + tunnelSession.IP);
                            var data = new List<byte>();
                            data.Add(0x04);
                            data.AddRange(iplengthbytes);
                            data.AddRange(ipbytes);
                            data.AddRange(sessionidbytes);
                            data.AddRange(orderbytes);
                            towrite = data.ToArray();
                            data.Clear();
                        }
                        else
                        {
                            var orderbytes = BitConverter.GetBytes(tunnelSession.order);
                            var lengthbytes = BitConverter.GetBytes(tunnelSession.Data.Length);

                            //Console.WriteLine("outgoing sender: " + tunnelSession.IP);
                            var data = new List<byte>();
                            data.Add(0x02);
                            data.AddRange(iplengthbytes);
                            data.AddRange(ipbytes);
                            data.AddRange(sessionidbytes);
                            data.AddRange(orderbytes);
                            data.AddRange(lengthbytes);
                            data.AddRange(tunnelSession.Data);
                            towrite = data.ToArray();
                            data.Clear();
                        }
                    }
                }
                if (towrite != null)
                {
                    encryptedStream.Write(towrite);
                    encryptedStream.Flush();
                }
                if (keepalivesw.ElapsedMilliseconds > 10000)
                {
                    keepalivesw.Restart();
                    encryptedStream.Write(new byte[] { 0x10 });
                    encryptedStream.Flush();
                }
                if (!tcptunnel.DataAvailable && senderqueue.Count == 0 && nexthopqueue.Count == 0)
                {
                    Thread.Sleep(1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.StackTrace);
                throw;
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
void ClientHandler(TcpClient client, ulong currentID = ulong.MaxValue, string IP = "")
{
    string endpoint = "";
    bool encryptfornext = false;
    try
    {
        var foundtundevice = false;
        var taps = TunTapHelper_windows.GetTapGuidList("tap0901");
        TunTapDevice tundevice = null;
        foreach (var tap in taps)
        {
            tundevice = new TunTapDevice(tap);
            if (tundevice.GetMTU() != -1)
            {
                foundtundevice = true;
                break;
            }
        }
        if (!foundtundevice)
        {
            var tapinfo = new TunTapHelper.TunTapDeviceInfo();
            tapinfo.Name = "SimpleTLSTunnel";
            tapinfo.Guid = "{" + Guid.NewGuid().ToString().ToUpper() + "}";
            tundevice = new TunTapDevice(tapinfo);
        }
        var version = tundevice.GetVersion();
        //tundevice.SetDHCPState(0);
        tundevice.SetConnectionState(TunTapHelper.ConnectionStatus.Connected);
        SetIP(tundevice.Name, IPAddress.Parse("10.10.1.1"), IPAddress.Parse("255.255.0.0"));
        var streamcreated = tundevice.CreateDeviceIOStream(1500);
        var stream = tundevice.TunTapDeviceIOStream;
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
        //Console.WriteLine(String.Format("Incoming Connection From: {0}", IP));

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
        //nextConnection = new TcpClient(config.nextHop_address, config.nextHop_port);
        //nextConnection.ReceiveTimeout = 30000;
        //nextConnection.SendTimeout = 30000;
        hopStream = stream;
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
                if (sw.ElapsedMilliseconds > 10000 || !responsesDict.ContainsKey(currentID))
                    break;
                var read = 0;
                byte[] towrite = null;
                lock (ttlock)
                {
                    if (responsesDict[currentID].Count > 0 && responsesDict[currentID].ContainsKey(readorder))
                    {
                        Console.WriteLine(readorder);
                        sw.Restart();
                        //var bbbb = new byte[65536];
                        //do
                        //{
                        //    read = sslStream.Read(bbbb, 0, bbbb.Length);
                        //    buffer.AddRange(bbbb.Take(read));
                        //}
                        //while (clientstream.DataAvailable && read != 0);
                        //Console.Write(Encoding.ASCII.GetString(buffer.ToArray()));
                        byte[] data = responsesDict[currentID][readorder].data;
                        if (data.Length == 1 && data[0] == 0x04)
                        {
                        }
                        else
                        {
                            towrite = data;
                        }
                        responsesDict[currentID].Remove(readorder);
                        readorder++;
                        //buffer.Clear();
                    }
                }
                if (towrite != null)
                {
                    hopStream.Write(towrite);
                    hopStream.Flush();
                }
                {
                    var bbbb = new byte[65536];
                    //do
                    //{
                    read = hopStream.Read(bbbb, 0, bbbb.Length);
                    hopStream.Flush();
                    buffer.AddRange(bbbb.Take(read));
                    //} while (nextConnection.Available > 0 && read != 0);
                    //sslStream.Write(buffer.ToArray());
                    lock (ttlock)
                        senderqueue.Enqueue(new TunnelSession() { ID = currentID, Data = buffer.ToArray(), order = writeorder, IP = IP, ts = DateTime.Now });
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
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.StackTrace);
    }
    try
    {
        lock (ttlock)
            responsesDict.Remove(currentID);
    }
    catch
    {

    }
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
        sslStream.WriteByte(0x00);
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
                lock (ttlock)
                {
                    if (stableTunnelsCount < maxStableTunnelsCount)
                    {
                        stableTunnelsCount++;
                        sslStream.Write(new byte[] { 0x01 });
                        sslStream.Flush();
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
        sslStream.WriteByte(0x00);
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
bool SetIP(string networkInterfaceName, IPAddress ipAddress, IPAddress subnetMask, IPAddress gateway = null)
{
    var process = new Process
    {
        StartInfo = new ProcessStartInfo("netsh", $"interface ip set address \"{networkInterfaceName}\" static {ipAddress} {subnetMask} " + (gateway == null ? "" : $"{gateway} 1"))
    };
    process.Start();
    process.WaitForExit();
    var successful = process.ExitCode == 0;
    process.Dispose();
    return successful;
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