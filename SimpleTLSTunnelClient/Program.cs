using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;
using Newtonsoft.Json;
using SimpleTLSTunnelClient;
using System.Security.Cryptography;
using System.Reflection.Metadata.Ecma335;
using System.Collections.Concurrent;
using System.Drawing.Drawing2D;

object tlock = new object();
ulong lastSessionID = 0;
var stableTunnelsCount = 0;
var maxStableTunnelsCount = 1;
ConcurrentQueue<TunnelSession> senderqueue = new ConcurrentQueue<TunnelSession>();
Dictionary<ulong, Dictionary<ulong, Packet>> responsesDict = new Dictionary<ulong, Dictionary<ulong, Packet>>();
TTunnelClientConfig config = null;
if (!File.Exists("config.json"))
{
    config = new TTunnelClientConfig();
    File.WriteAllText("config.json", JsonConvert.SerializeObject(config));
}
else
{
    config = JsonConvert.DeserializeObject<TTunnelClientConfig>(File.ReadAllText("config.json"));
}
//var encrypted=Encrypt(Encoding.ASCII.GetBytes("fuckme"));
//var decrypted=Decrypt(encrypted);
//var dectext = Encoding.ASCII.GetString(decrypted);
var cert = new X509Certificate2("cert.crt");
bool userCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
{
    //var servercert = certificate as X509Certificate2;
    //if (certificate.GetSerialNumberString() == cert.GetSerialNumberString())
    //    return true;
    //else
    //    return false;
    return true;
}
void StableTunnelHandler()
{
    try
    {
        var tunnelsw = new Stopwatch();
        tunnelsw.Start();
        var sw = new Stopwatch();
        sw.Start();
        stableTunnelsCount++;
        var client = new TcpClient(config.server_address, config.server_port);
        client.ReceiveTimeout = 30000;
        client.SendTimeout = 30000;
        NetworkStream tcptunnel = client.GetStream();
        var encryptedStream = new SslStream(tcptunnel, true, userCertificateValidationCallback, userCertificateSelectionCallback);

        encryptedStream.AuthenticateAsClient("", null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
        encryptedStream.Flush();
        while (true)
        {
            try
            {
                lock (tlock)
                {
                    while (senderqueue.Count > 0 && (DateTime.Now - senderqueue.FirstOrDefault().ts).TotalSeconds > 30)
                    {
                        TunnelSession tunnelSession = null;
                        senderqueue.TryDequeue(out tunnelSession);
                    }
                }
                if (!client.Connected || sw.ElapsedMilliseconds > 30000)
                {
                    break;
                }
                if (client.Available > 0)
                {
                    sw.Restart();
                    var type = encryptedStream.ReadByte();
                    if (type == 0x02)
                    {
                        var sessionidbytes = new byte[8];
                        var orderbytes = new byte[8];
                        var lengthbytes = new byte[4];
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
                        if (responsesDict.ContainsKey(sessionid))
                        {
                            responsesDict[sessionid].Add(order, new Packet() { data = data.ToArray(), ts = DateTime.Now });
                        }
                        data.Clear();
                    }
                }
                lock (tlock)
                {
                    if (senderqueue.Count > 0)
                    {
                        sw.Restart();
                        TunnelSession tunnelSession = null;
                        senderqueue.TryDequeue(out tunnelSession);
                        var sessionidbytes = BitConverter.GetBytes(tunnelSession.ID);
                        var orderbytes = BitConverter.GetBytes(tunnelSession.order);
                        var lengthbytes = BitConverter.GetBytes(tunnelSession.Data.Length);
                        var data = new List<byte>();
                        data.Add(0x02);
                        data.AddRange(sessionidbytes);
                        data.AddRange(orderbytes);
                        data.AddRange(BitConverter.GetBytes(0));
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
                if (!tcptunnel.DataAvailable)
                {
                    Thread.Sleep(1);
                }
            }
            catch
            {

            }
        }
    }
    catch
    {

    }
    stableTunnelsCount--;
}
void ClientHandler(TcpClient client)
{
    string endpoint = "";
    var currentID = lastSessionID;
    lastSessionID++;
    if (lastSessionID >= ulong.MaxValue)
    {
        lastSessionID = 0;
    }
    try
    {
        ulong readorder = 0;
        ulong writeorder = 0;
        var buffer = new List<byte>();
        NetworkStream clientstream = client.GetStream();
        endpoint = clientstream.Socket.RemoteEndPoint.ToString();
        Console.WriteLine(String.Format("Incoming Connection From: {0}", endpoint));
        bool sfirst = true, rfirst = true;
        var pinger = new Stopwatch();
        responsesDict.Add(currentID, new Dictionary<ulong, Packet>());
        var sw = new Stopwatch();
        sw.Start();
        while (true)
        {
            try
            {
                if (!client.Connected || sw.ElapsedMilliseconds > 10000)
                    break;
                var read = 0;
                if (clientstream.DataAvailable)
                {
                    sw.Restart();
                    var bbbb = new byte[65536];
                    //do
                    {
                        read = clientstream.Read(bbbb, 0, bbbb.Length);
                        buffer.AddRange(bbbb.Take(read));
                    }
                    //while (clientstream.DataAvailable && read != 0);
                    //encryptedStream.Write(buffer.ToArray());
                    senderqueue.Enqueue(new TunnelSession() { ID = currentID, Data = buffer.ToArray(), order = writeorder, ts = DateTime.Now });
                    writeorder++;
                    buffer.Clear();
                    if (sfirst)
                    {
                        pinger.Start();
                    }
                    sfirst = false;
                }
                lock (tlock)
                {
                    if (responsesDict[currentID].Count > 0 && responsesDict[currentID].ContainsKey(readorder))
                    {
                        sw.Restart();
                        byte[] bbbb = responsesDict[currentID][readorder].data;
                        //do
                        //{
                        //    read = encryptedStream.Read(bbbb, 0, bbbb.Length);
                        //    buffer.AddRange(bbbb.Take(read));
                        //} while (tcptunnel.DataAvailable && read != 0);
                        clientstream.Write(bbbb);
                        clientstream.Flush();
                        readorder++;
                        //Console.Write(Encoding.ASCII.GetString(buffer.ToArray()));
                        buffer.Clear();
                        if (rfirst)
                        {
                            Console.WriteLine("Request Ping {0}", pinger.ElapsedMilliseconds);
                            pinger.Stop();
                        }
                        rfirst = false;
                    }
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


        //encryptedStream.Close();
        //tcptunnel.Close();
        client.Close();
    }
    catch
    {

    }
    responsesDict.Remove(currentID);
    Console.WriteLine(String.Format("Dropped Connection From: {0}", endpoint));
}

X509Certificate userCertificateSelectionCallback(object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate? remoteCertificate, string[] acceptableIssuers)
{
    return cert as X509Certificate;
}

var tcplistener = new TcpListener(System.Net.IPAddress.Any, config.proxy_listening_port);
tcplistener.Start();
while (true)
{
    if (tcplistener.Pending())
    {
        new Thread(() =>
        {
            ClientHandler(tcplistener.AcceptTcpClient());
        }).Start();
    }
    if (stableTunnelsCount < maxStableTunnelsCount)
    {
        try
        {
            new Thread(() =>
            {
                StableTunnelHandler();
            }).Start();
        }
        catch
        {

        }
    }
    Thread.Sleep(100);
}