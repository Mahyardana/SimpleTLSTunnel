using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;

var cert = new X509Certificate("cert.pfx");
void ClientHandler(TcpClient client)
{
    var sw = new Stopwatch();
    sw.Start();
    NetworkStream clientstream = client.GetStream();
    string endpoint = clientstream.Socket.RemoteEndPoint.ToString();
    Console.WriteLine(String.Format("Incoming Connection From: {0}", endpoint));
    var sslStream = new SslStream(clientstream, true, userCertificateValidationCallback);
    sslStream.AuthenticateAsServer(cert, false, false);
    var buffer = new List<byte>();
    NetworkStream sockstcp = new TcpClient("127.0.0.1", 8080).GetStream();
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
                while (clientstream.DataAvailable);
                //Console.Write(Encoding.ASCII.GetString(buffer.ToArray()));
                sockstcp.Write(buffer.ToArray());
                buffer.Clear();
            }
            else if (sockstcp.DataAvailable)
            {
                sw.Restart();
                var bbbb = new byte[65536];
                do
                {
                    read = sockstcp.Read(bbbb, 0, bbbb.Length);
                    buffer.AddRange(bbbb.Take(read));
                } while (sockstcp.DataAvailable);
                sslStream.Write(buffer.ToArray());
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
    sockstcp.Close();
    sslStream.Close();
    clientstream.Close();
    Console.WriteLine(String.Format("Dropped Connection From: {0}", endpoint));
}

bool userCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
{
    return true;
}

var tcplistener = new TcpListener(System.Net.IPAddress.Any, 443);
tcplistener.Start();
var socksServer = new Socks5.Servers.SimpleSocks5Server(new System.Net.IPEndPoint(System.Net.IPAddress.Any, 8080));
socksServer.StartAsync();
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