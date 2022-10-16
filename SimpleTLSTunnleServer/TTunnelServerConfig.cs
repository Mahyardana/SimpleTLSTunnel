using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleTLSTunnleServer
{
    public class TTunnelServerConfig
    {
        public string nextHop_address = "127.0.0.1";
        public int nextHop_port = 8080;
        public int ListeningPort = 443;
        public string Key = "";
    }
}
