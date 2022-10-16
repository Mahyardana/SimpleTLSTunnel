using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;
using Newtonsoft;
using SimpleTLSTunnleServer;
using Newtonsoft.Json;
using System.Security.Cryptography;

var csp = new RNGCryptoServiceProvider();
byte[] AESKEY = null;
byte[] GenerateBytes(int size)
{
    var rnd = new byte[size];
    csp.GetBytes(rnd);
    return rnd;
}
byte[] Encrypt(byte[] data)
{
    SHA256 sha256 = SHA256.Create();
    var hash = sha256.ComputeHash(data);
    var aes = new AesGcm(AESKEY);
    var ciphertext = new byte[data.Length];
    byte[] nonce = GenerateBytes(12);
    byte[] tag = new byte[16];
    aes.Encrypt(nonce, data, ciphertext, tag);
    var totransfer = new List<byte>();
    totransfer.AddRange(nonce);
    totransfer.AddRange(tag);
    totransfer.AddRange(hash);
    totransfer.AddRange(BitConverter.GetBytes(ciphertext.Length));
    totransfer.AddRange(ciphertext);
    return totransfer.ToArray();
}
byte[] Decrypt(byte[] ciphertext)
{
    try
    {
        SHA256 sha256 = SHA256.Create();
        var aes = new AesGcm(AESKEY);
        byte[] nonce = ciphertext.Take(new Range(0, 12)).ToArray();
        byte[] tag = ciphertext.Take(new Range(12, 28)).ToArray();
        var datahash = ciphertext.Take(new Range(28, 60)).ToArray();
        int length = BitConverter.ToInt32(ciphertext.Take(new Range(60, 64)).ToArray());
        var cipher = ciphertext.Take(new Range(64, 64 + length)).ToArray();
        var data = new byte[cipher.Length];
        aes.Decrypt(nonce, cipher, tag, data);
        var hash = sha256.ComputeHash(data);
        if (hash.SequenceEqual(datahash))
            return data;
        else
            return new byte[0];
    }
    catch
    {
        return new byte[0];
    }
}


TTunnelServerConfig config = null;
if (!File.Exists("config.json"))
{
    config = new TTunnelServerConfig();
    AESKEY = GenerateBytes(32);
    var key = Convert.ToHexString(AESKEY);
    config.Key = key;
    File.WriteAllText("config.json", JsonConvert.SerializeObject(config));
}
else
{
    config = JsonConvert.DeserializeObject<TTunnelServerConfig>(File.ReadAllText("config.json"));
    AESKEY = Convert.FromHexString(config.Key);
}


var cert = new X509Certificate("cert.pfx");
void ClientHandler(TcpClient client)
{
    string endpoint = "";
    bool encryptfornext = false;
    try
    {
        var rbuffer = new List<byte>();
        var sbuffer = new List<byte>();
        var sw = new Stopwatch();
        sw.Start();
        NetworkStream clientstream = client.GetStream();
        endpoint = clientstream.Socket.RemoteEndPoint.ToString();
        Console.WriteLine(String.Format("Incoming Connection From: {0}", endpoint)); 
        TcpClient nextConnection = new TcpClient(config.nextHop_address, config.nextHop_port);
        Stream hopStream = nextConnection.GetStream();
        if (config.nextHop_address != "" && config.nextHop_address != "127.0.0.1")
        {
            encryptfornext = true;
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
                        read = clientstream.Read(bbbb, 0, bbbb.Length);
                        rbuffer.AddRange(bbbb.Take(read));
                    }
                    while (clientstream.DataAvailable && read != 0);
                    //Console.Write(Encoding.ASCII.GetString(buffer.ToArray()));
                    var dec = Decrypt(rbuffer.ToArray());
                    if (dec.Length > 0)
                    {
                        rbuffer.RemoveRange(0, dec.Length + 64);
                    }
                    if (encryptfornext)
                    {
                        var enc=Encrypt(dec);
                        hopStream.Write(enc);
                    }
                    else
                    {
                        hopStream.Write(dec);
                    }
                }
                if (nextConnection.Available > 0)
                {
                    sw.Restart();
                    var bbbb = new byte[65536];
                    do
                    {
                        read = hopStream.Read(bbbb, 0, bbbb.Length);
                        sbuffer.AddRange(bbbb.Take(read));
                    } while (nextConnection.Available > 0 && read != 0);
                    if (encryptfornext)
                    {
                        var dec = Decrypt(sbuffer.ToArray());
                        if (dec.Length > 0)
                        {
                            sbuffer.RemoveRange(0, dec.Length + 64);
                        }
                        var enc = Encrypt(dec);
                        clientstream.Write(enc);
                    }
                    else
                    {
                        //if (buffer.Count > 16000)
                        //{
                        //    while(buffer.Count> 16000)
                        //    {
                        //        var enc = Encrypt(buffer.GetRange(0, 65400).ToArray());
                        //        buffer.RemoveRange(0, 65400);
                        //        clientstream.Write(enc);
                        //    }
                        //    var lastenc = Encrypt(buffer.ToArray());
                        //    clientstream.Write(lastenc);
                        //} 
                        //else
                        {
                            var enc = Encrypt(sbuffer.ToArray());
                            if (enc.Length > 0)
                            {
                                sbuffer.RemoveRange(0, enc.Length - 64);
                            }
                            clientstream.Write(enc);
                        }
                    }
                }
                if (rbuffer.Count > 0 || sbuffer.Count > 0)
                {

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
if (config.nextHop_address == "" || config.nextHop_address == "127.0.0.1")
{
    var socksServer = new Socks5.Servers.SimpleSocks5Server(new System.Net.IPEndPoint(System.Net.IPAddress.Any, config.nextHop_port));
    socksServer.StartAsync();
}
while (true)
{
    if (tcplistener.Pending())
    {
        new Thread(() =>
        {
            ClientHandler(tcplistener.AcceptTcpClient());
        }).Start();
    }
    Thread.Sleep(100);
}