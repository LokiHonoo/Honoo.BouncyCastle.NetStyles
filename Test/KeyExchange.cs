using Honoo.BouncyCastle;
using System;
using System.Linq;

namespace Test
{
    internal static class KeyExchange
    {
        internal static void Test()
        {
            Demo();
            Console.ReadKey(true);
        }

        private static void Demo()
        {
            IECDHTerminalA ecdhA = new ECDH().GetTerminalAInterface();
            IECDHTerminalB ecdhB = new ECDH().GetTerminalBInterface();

            // Alice work
            ecdhA.GenerateParameters(384);
            byte[] p = ecdhA.P;
            byte[] g = ecdhA.G;
            byte[] publicKeyA = ecdhA.PublicKeyA;

            // Bob work
            ecdhB.GenerateParameters(p, g, publicKeyA);
            byte[] pmsB = ecdhB.DeriveKeyMaterial(true);
            byte[] publicKeyB = ecdhB.PublicKeyB;

            // Alice work
            byte[] pmsA = ecdhA.DeriveKeyMaterial(publicKeyB, true);
            
            //
            bool same = pmsA.SequenceEqual(pmsB);
            Console.WriteLine($"ECDH {same}");
            Console.WriteLine(BitConverter.ToString(pmsA).Replace("-", ""));
            Console.WriteLine(BitConverter.ToString(pmsB).Replace("-", ""));
        }
    }
}