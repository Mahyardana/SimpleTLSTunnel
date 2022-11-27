using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;
using Newtonsoft.Json;
using SimpleTLSTunnelClient;
using System.Security.Cryptography;
using System.Reflection.Metadata.Ecma335;
using System.Collections;

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
var random = RandomNumberGenerator.Create();
byte[] Encrypt(AesGcm aes, byte[] bytes)
{
    byte[] cipher = new byte[bytes.Length];
    byte[] nonce = new byte[12];
    byte[] tag = new byte[16];
    //var arr1 = new BitArray(hash.Take(16).ToArray());
    //var arr2 = new BitArray(hash.Take(Range.StartAt(16)).ToArray());
    //var xor=arr1.Xor(arr2);
    //hash.CopyTo(tag, 0);
    var res = new List<byte>();
    random.GetBytes(nonce, 0, nonce.Length);
    res.AddRange(nonce);
    aes.Encrypt(nonce, bytes, cipher, tag);
    res.AddRange(tag);
    res.AddRange(cipher);
    return res.ToArray();
}


byte[] Decrypt(AesGcm aes, byte[] encrypted)
{
    var res = new List<byte>(encrypted);
    byte[] plain = new byte[encrypted.Length - 12 - 16];
    byte[] nonce = res.Take(12).ToArray();
    res.RemoveRange(0, nonce.Length);
    byte[] tag = res.Take(16).ToArray();
    res.RemoveRange(0, tag.Length);
    aes.Decrypt(nonce, res.ToArray(), tag, plain);
    return plain;
}
//var testkey = new byte[16];
//random.GetBytes(testkey);
//var aestest = new AesGcm(testkey);
//for(int i=0;i<10000000;i++)
//{
//    var encrypted = Encrypt(aestest, Encoding.ASCII.GetBytes("Hello Test!!!!!!!!.........."));
//    var decrypted = Decrypt(aestest, encrypted);
//    var dectext = Encoding.ASCII.GetString(decrypted);
//}

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
void ClientHandler(TcpClient client)
{
    string endpoint = "";
    try
    {
        var buffer = new List<byte>();
        var sw = new Stopwatch();
        sw.Start();
        NetworkStream clientstream = client.GetStream();
        endpoint = clientstream.Socket.RemoteEndPoint.ToString();
        Console.WriteLine(String.Format("Incoming Connection From: {0}", endpoint));
        //NetworkStream tcptunnle = new TcpClient(config.server_address, config.server_port).GetStream();
        var socket = new Socket(SocketType.Stream, ProtocolType.IP);
        socket.Connect(config.server_address, config.server_port);
        var key = new byte[16];
        random.GetBytes(key, 0, key.Length);
        var aes = new AesGcm(key);
        //var encryptedStream = new SslStream(tcptunnle, true, userCertificateValidationCallback, userCertificateSelectionCallback);
        //encryptedStream.AuthenticateAsClient("", null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
        socket.Send(new byte[] { 0x00 });
        var byteget = new byte[1]; 
        socket.Receive(byteget, 0, 1, SocketFlags.None);
        var res = byteget[0];
        if (res != 0x01)
        {
            client.Close();
            return;
        }
        var len = new byte[4];
        socket.Receive(len, 0, len.Length,SocketFlags.None);
        var length = BitConverter.ToInt32(len, 0);
        var buffer1 = new byte[length];
        socket.Receive(buffer1, 0, length, SocketFlags.None);
        var x509 = RSA.Create();
        int rsaread = 0;
        x509.ImportRSAPublicKey(buffer1, out rsaread);
        var encryptedkey = x509.Encrypt(key, RSAEncryptionPadding.OaepSHA1);
        socket.Send(new byte[] { 0x02 });
        socket.Send(BitConverter.GetBytes(encryptedkey.Length));
        socket.Send(encryptedkey);
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
                        buffer.AddRange(bbbb.Take(read));
                    } while (clientstream.DataAvailable && read != 0);
                    var enc = Encrypt(aes, buffer.ToArray());
                    socket.Send(new byte[] { 0x03 });
                    socket.Send(BitConverter.GetBytes(enc.Length));
                    socket.Send(enc);
                    //encryptedStream.Write(buffer.ToArray());
                    buffer.Clear();
                }
                if (socket.Available>0)
                {
                    sw.Restart();
                    socket.Receive(byteget,0,1,SocketFlags.None);
                    res = byteget[0];
                    len = new byte[4];
                    var bbbb = new byte[65536];
                    socket.Receive(len, 0, len.Length,SocketFlags.None);
                    length = BitConverter.ToInt32(len, 0);
                    if (res == 0x03)
                    {
                        read = 0;
                        do
                        {
                            var toread = length - buffer.Count;
                            read = socket.Receive(bbbb, 0, bbbb.Length > toread ? toread : bbbb.Length,SocketFlags.None);
                            buffer.AddRange(bbbb.Take(read));
                        } while (buffer.Count < length);
                        var dec = Decrypt(aes, buffer.ToArray());
                        clientstream.Write(dec, 0, dec.Length);
                        buffer.Clear();
                    }
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


        //encryptedStream.Close();
        socket.Close();
        client.Close();
    }
    catch
    {

    }

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
    Thread.Sleep(100);
}