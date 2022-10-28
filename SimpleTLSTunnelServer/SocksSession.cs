using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SimpleTLSTunnelServer
{
    internal class SocksSession
    {
        public TcpClient client;
        public ulong writeorder = 1;
        public ulong readorder = 2;
        public ulong expectedack = 0;
        public int packetsforack = 0;
    }
}
