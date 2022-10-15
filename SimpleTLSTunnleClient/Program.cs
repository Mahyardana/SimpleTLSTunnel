using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;

var SERVER_IP = "XXX.XXX.XXX.XXX";

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
    var sw = new Stopwatch();
    sw.Start();
    NetworkStream clientstream = client.GetStream();
    string endpoint = clientstream.Socket.RemoteEndPoint.ToString();
    Console.WriteLine(String.Format("Incoming Connection From: {0}", endpoint));
    var buffer = new List<byte>();
    NetworkStream tcptunnle = new TcpClient(SERVER_IP, 443).GetStream();
    var sslStream = new SslStream(tcptunnle, true, userCertificateValidationCallback, userCertificateSelectionCallback);
    sslStream.AuthenticateAsClient(SERVER_IP);
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
                } while (clientstream.DataAvailable);
                sslStream.Write(buffer.ToArray());
                buffer.Clear();
            }
            else if (tcptunnle.DataAvailable)
            {
                sw.Restart();
                var bbbb = new byte[65536];
                do
                {
                    read = sslStream.Read(bbbb, 0, bbbb.Length);
                    buffer.AddRange(bbbb.Take(read));
                } while (tcptunnle.DataAvailable);
                clientstream.Write(buffer.ToArray());
                //Console.Write(Encoding.ASCII.GetString(buffer.ToArray()));
                buffer.Clear();
            }
            else
            {
                Thread.Sleep(10);
            }
            if (!client.Connected || sw.Elapsed.TotalSeconds >= 10)
                break;
        }
        catch
        {

        }

    }


    sslStream.Close();
    tcptunnle.Close();
    client.Close();

    Console.WriteLine(String.Format("Dropped Connection From: {0}", endpoint));
}

X509Certificate userCertificateSelectionCallback(object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate? remoteCertificate, string[] acceptableIssuers)
{
    return cert as X509Certificate;
}

var tcplistener = new TcpListener(System.Net.IPAddress.Loopback, 1080);
tcplistener.Start();
while (true)
{
    if (tcplistener.Pending())
    {
        Task.Run(() =>
        {
            ClientHandler(tcplistener.AcceptTcpClient());
        });
    }
    Thread.Sleep(100);
}