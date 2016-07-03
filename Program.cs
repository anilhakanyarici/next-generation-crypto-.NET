using System;
using System.Collections.Generic;
using System.Text;

namespace System.Security.Cryptography
{
    class Program
    {
        static void Main(string[] args)
        {
            ECDSACryptoServiceProvider.ECDSAStressTest(CurveName.SECP521R1, false);
        }
    }
}
