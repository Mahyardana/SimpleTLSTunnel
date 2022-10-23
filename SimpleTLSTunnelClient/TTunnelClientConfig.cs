using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleTLSTunnelClient
{
    public class TTunnelClientConfig
    {
        public int stable_tunnels = 32;
        public string server_address = "127.0.0.1";
        public int server_port = 443;
        public int proxy_listening_port = 1080;
    }
}
