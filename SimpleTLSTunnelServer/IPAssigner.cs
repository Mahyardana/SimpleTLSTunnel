using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SimpleTLSTunnelServer
{
    class SessionIP
    {
        public DateTime time;
        public IPAddress address;
    }
    internal class IPAssigner
    {
        IPAddress RangeStart;
        IPAddress RangeEnd;
        byte[] currentip = null;
        public IPAssigner(IPAddress start, IPAddress end)
        {
            RangeStart = start;
            RangeEnd = end;
        }
        public IPAddress GetNewIP()
        {
            if (currentip == null)
            {
                currentip = RangeStart.GetAddressBytes();
            }
            else
            {
                if (currentip[3] != 0xff)
                    currentip[3]++;
                else
                {
                    currentip[3] = 0x01;
                    currentip[2]++;
                }
                if (BitConverter.ToInt32(currentip.Reverse().ToArray()) >= BitConverter.ToInt32(RangeEnd.GetAddressBytes().Reverse().ToArray()))
                {
                    currentip = RangeStart.GetAddressBytes();
                }
            }
            return new IPAddress(currentip);
        }
    }
}
