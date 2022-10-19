using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleTLSTunnelServer
{
    internal class TunnelSession
    {
        public ulong ID;
        public ulong order;
        public string IP;
        public byte[] Data;
    }
}
