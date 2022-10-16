using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;
using Newtonsoft.Json;
using SimpleTLSTunnleClient;
using System.Security.Cryptography;
using System.Reflection.Metadata.Ecma335;

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
        var cipher = ciphertext.Take(new Range(64, 64+length)).ToArray();
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

TTunnelClientConfig config = null;
if (!File.Exists("config.json"))
{
    config = new TTunnelClientConfig();
    AESKEY = GenerateBytes(32);
    var key = Convert.ToHexString(AESKEY);
    config.Key = key;
    File.WriteAllText("config.json", JsonConvert.SerializeObject(config));
}
else
{
    config = JsonConvert.DeserializeObject<TTunnelClientConfig>(File.ReadAllText("config.json"));
    AESKEY = Convert.FromHexString(config.Key);
}
//var encrypted=Encrypt(Encoding.ASCII.GetBytes("fuckme"));
//var decrypted=Decrypt(encrypted);
//var dectext = Encoding.ASCII.GetString(decrypted);
var cert = new X509Certificate2("cert.crt");
bool userCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
{
    var servercert = certificate as X509Certificate2;
    if (certificate.GetSerialNumberString() == cert.GetSerialNumberString())
        return true;
    else
        return false;
}
void ClientHandler(TcpClient client)
{
    string endpoint = "";
    try
    {
        var rbuffer = new List<byte>();
        var sbuffer = new List<byte>();
        var sw = new Stopwatch();
        sw.Start();
        NetworkStream clientstream = client.GetStream();
        endpoint = clientstream.Socket.RemoteEndPoint.ToString();
        Console.WriteLine(String.Format("Incoming Connection From: {0}", endpoint));
        NetworkStream tcptunnle = new TcpClient(config.server_address, config.server_port).GetStream();
        var encryptedStream = tcptunnle;
        //new SslStream(tcptunnle, true, userCertificateValidationCallback, userCertificateSelectionCallback);

        //encryptedStream.AuthenticateAsClient("", null,System.Security.Authentication.SslProtocols.Tls12|System.Security.Authentication.SslProtocols.Tls13,false);
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
                    } while (clientstream.DataAvailable && read != 0);
                    var enc=Encrypt(rbuffer.ToArray());
                    encryptedStream.Write(enc);
                    if(enc.Length>0)
                    {
                        rbuffer.RemoveRange(0, enc.Length - 64);
                    }
                }
                if (tcptunnle.DataAvailable)
                {
                    sw.Restart();
                    var bbbb = new byte[65536];
                    do
                    {
                        read = encryptedStream.Read(bbbb, 0, bbbb.Length);
                        sbuffer.AddRange(bbbb.Take(read));
                    } while (tcptunnle.DataAvailable && read != 0);
                    var dec=Decrypt(sbuffer.ToArray());
                    clientstream.Write(dec);
                    if(dec.Length>0)
                    {
                        sbuffer.RemoveRange(0, dec.Length + 64);
                    }
                    //Console.Write(Encoding.ASCII.GetString(buffer.ToArray()));
                }
                if(sbuffer.Count>0)
                {
                    var dec = Decrypt(sbuffer.ToArray());
                    clientstream.Write(dec);
                    if (dec.Length > 0)
                    {
                        sbuffer.RemoveRange(0, dec.Length + 64);
                    }
                }
                if (read == 0)
                {
                    Thread.Sleep(1);
                }
                if(rbuffer.Count>0||sbuffer.Count>0)
                {

                }
                if (!client.Connected || sw.Elapsed.TotalSeconds >= 10)
                    break;
            }
            catch
            {

            }

        }


        encryptedStream.Close();
        tcptunnle.Close();
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

var tcplistener = new TcpListener(System.Net.IPAddress.Loopback, config.proxy_listening_port);
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
    Thread.Sleep(100);
}