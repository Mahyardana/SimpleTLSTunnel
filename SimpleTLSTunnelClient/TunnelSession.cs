using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleTLSTunnelClient
{
    internal class TunnelSession
    {
        public ulong ID;
        public ulong order;
        public byte[] Data;
        public DateTime ts;
        public bool close = false;
        public bool ack = false;
    }
}
