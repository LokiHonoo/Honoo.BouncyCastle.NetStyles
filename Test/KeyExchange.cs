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
            IKeyExchangeA keA = new ECDH().GetPartyAInterface();
            IKeyExchangeB keB = new ECDH().GetPartyBInterface();

            // Alice work
            keA.GenerateParameters(384);
            byte[] p = keA.P;
            byte[] g = keA.G;
            byte[] publicKeyA = keA.PublicKeyA;

            // Bob work
            keB.GenerateParameters(p, g, publicKeyA);
            byte[] pmsB = keB.DeriveKeyMaterial(true);
            byte[] publicKeyB = keB.PublicKeyB;

            // Alice work
            byte[] pmsA = keA.DeriveKeyMaterial(publicKeyB, true);

            //
            bool same = pmsA.SequenceEqual(pmsB);
            Console.WriteLine($"ECDH {same}");
            Console.WriteLine(BitConverter.ToString(pmsA).Replace("-", ""));
            Console.WriteLine(BitConverter.ToString(pmsB).Replace("-", ""));
        }
    }
}