using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;
using Newtonsoft.Json;
using SimpleTLSTunnleClient;
using System.Security.Cryptography;
using System.Reflection.Metadata.Ecma335;


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
        NetworkStream tcptunnle = new TcpClient(config.server_address, config.server_port).GetStream();
        var encryptedStream = new SslStream(tcptunnle,true, userCertificateValidationCallback);

        encryptedStream.AuthenticateAsClient(config.server_address);
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
                    encryptedStream.Write(buffer.ToArray());
                    buffer.Clear();
                }
                if (tcptunnle.DataAvailable)
                {
                    sw.Restart();
                    var bbbb = new byte[65536];
                    do
                    {
                        read = encryptedStream.Read(bbbb, 0, bbbb.Length);
                        buffer.AddRange(bbbb.Take(read));
                    } while (tcptunnle.DataAvailable && read != 0);
                    clientstream.Write(buffer.ToArray());
                    //Console.Write(Encoding.ASCII.GetString(buffer.ToArray()));
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


        encryptedStream.Close();
        tcptunnle.Close();
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