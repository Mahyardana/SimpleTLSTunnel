using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;
using Newtonsoft;
using SimpleTLSTunnleServer;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Net;
using System.Collections.Concurrent;

object tlock = new object();
ConcurrentQueue<TcpClient> backConnects = new ConcurrentQueue<TcpClient>();

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
void ClientHandler(TcpClient client)
{
    string endpoint = "";
    bool encryptfornext = false;
    try
    {
        var buffer = new List<byte>();
        var sw = new Stopwatch();
        sw.Start();
        if (client == null)
        {
            client = new TcpClient(config.BackConnect_address, config.BackConnect_port);
            while (client.Available <= 0)
            {
                Thread.Sleep(1);
            }
        }

        NetworkStream clientstream = client.GetStream();
        endpoint = clientstream.Socket.RemoteEndPoint.ToString();

        var sslStream = new SslStream(clientstream, true, userCertificateValidationCallback);
        sslStream.AuthenticateAsServer(cert, false, false);
        Console.WriteLine(String.Format("Incoming Connection From: {0}", endpoint));

        TcpClient nextConnection = null;
        Stream hopStream = null;
        if (config.BackConnectCapability && config.BackConnect_address == "127.0.0.1")
        {
            lock (tlock)
            {
                connectionsRequired++;
            }
            int counter = 0;
            while (nextConnection == null)
            {
                if (backConnects.Count > 0)
                    backConnects.TryDequeue(out nextConnection);
                Thread.Sleep(1);
                counter++;
                if (counter >= 2000)
                    return;
            }
            hopStream = nextConnection.GetStream();
        }
        else
        {
            nextConnection = new TcpClient(config.nextHop_address, config.nextHop_port);
            hopStream = nextConnection.GetStream();
        }
        if (config.nextHop_address != "" && config.nextHop_address != "127.0.0.1")
        {
            hopStream = new SslStream(nextConnection.GetStream(), true, userCertificateValidationCallback);
            ((SslStream)hopStream).AuthenticateAsClient("", null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
        }
        while (true)
        {
            try
            {
                var read = 0;
                if (clientstream.DataAvailable)
                {
                    sw.Restart();
                    var bbbb = new byte[65536];
                    do
                    {
                        read = sslStream.Read(bbbb, 0, bbbb.Length);
                        buffer.AddRange(bbbb.Take(read));
                    }
                    while (clientstream.DataAvailable && read != 0);
                    //Console.Write(Encoding.ASCII.GetString(buffer.ToArray()));
                    hopStream.Write(buffer.ToArray());
                    buffer.Clear();
                }
                if (nextConnection.Available > 0)
                {
                    sw.Restart();
                    var bbbb = new byte[65536];
                    do
                    {
                        read = hopStream.Read(bbbb, 0, bbbb.Length);
                        buffer.AddRange(bbbb.Take(read));
                    } while (nextConnection.Available > 0 && read != 0);
                    sslStream.Write(buffer.ToArray());
                    buffer.Clear();
                }
                if (read == 0)
                {
                    Thread.Sleep(1);
                }
                if (!client.Connected || sw.Elapsed.TotalSeconds >= 10)
                    break;
            }
            catch
            {

            }

        }
        nextConnection.Close();
    }
    catch
    {

    }
    client.Close();
    Console.WriteLine(String.Format("Dropped Connection From: {0}", endpoint));
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
                    lock (tlock)
                    {
                        connectionsRequired--;
                    }
                }
                if (sw.ElapsedMilliseconds > 1000)
                {
                    sw.Restart();
                    sslStream.Write(new byte[] { 0x10 });
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
    }
    catch
    {

    }
    client.Close();
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
                            new Thread(() =>
                            {
                                ClientHandler(null);
                            }).Start();
                        }
                        else if(read == 0x10)
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
    }
    catch
    {

    }
    client.Close();
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
        if (client.Client.RemoteEndPoint.ToString().Contains(config.nextHop_address))
        {
            backConnects.Enqueue(client);
        }
        else
        {
            new Thread(() =>
            {
                ClientHandler(client);
            }).Start();
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
    Thread.Sleep(100);
}