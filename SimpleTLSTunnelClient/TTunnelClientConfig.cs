using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleTLSTunnleClient
{
    public class TTunnelClientConfig
    {
        public string server_address = "127.0.0.1";
        public int server_port_start = 443;
        public int server_port_end = 443;
        public int proxy_listening_port = 1080;
    }
}
