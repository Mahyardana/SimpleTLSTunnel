using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleTLSTunnelServer
{
    public class TTunnelServerConfig
    {
        public string nextHop_address = "127.0.0.1";
        public int nextHop_port = 8080;
        public int ListeningPort = 443;
        public bool BackConnectCapability = false;
        public string BackConnect_address = "127.0.0.1";
        public int BackConnectManager_port = 444;
        public int BackConnect_port = 443;
        public bool PortForwarding = false;
    }
}
