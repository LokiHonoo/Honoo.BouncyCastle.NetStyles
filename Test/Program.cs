using System;

namespace Test
{
    internal class Program
    {
        private static void Main()
        {
            while (true)
            {
                Console.Clear();
                Console.WriteLine("========================================================================================================================");
                Console.WriteLine();
                Console.WriteLine("                                     Honoo.BouncyCastle        Runtime version " + Environment.Version);
                Console.WriteLine();
                Console.WriteLine("========================================================================================================================");
                Console.WriteLine();
                Console.WriteLine("  1. Hash/HMAC/CMAC/MAC");
                Console.WriteLine("  2. Symmetric Encryption");
                Console.WriteLine("  3. Asymmetric Encryption");
                Console.WriteLine("  4. Signature");
                Console.WriteLine("  5. Certificate");
                Console.WriteLine("  6. ECDH Key Exchange");
                Console.WriteLine();
                Console.WriteLine("  7. Hash Speed");
                Console.WriteLine("  8. Symmetric Encryption Speed");
                Console.WriteLine();
                Console.WriteLine();
                Console.WriteLine("  Z. Temporaries");
                Console.WriteLine();
                Console.WriteLine();
                Console.Write("Choice a project:");
                while (true)
                {
                    var kc = Console.ReadKey(true).KeyChar;
                    switch (kc)
                    {
                        case '1': Console.Clear(); Hash.Test(); break;
                        case '2': Console.Clear(); Symmetric.Test(); break;
                        case '3': Console.Clear(); Asymmetric.Test(); break;
                        case '4': Console.Clear(); Signature.Test(); break;
                        case '6': Console.Clear(); KeyExchange.Test(); break;
                        case '7': Console.Clear(); HashSpeed.Test(); break;
                        case '8': Console.Clear(); SymmetricSpeed.Test(); break;
                        default: continue;
                    }
                    break;
                }
            }
        }
    }
}