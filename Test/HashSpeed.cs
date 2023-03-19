using Honoo.BouncyCastle;
using System;
using System.Diagnostics;

namespace Test
{
    internal static class HashSpeed
    {
        internal static void Test()
        {
            byte[] input = new byte[13000];
            Common.Random.NextBytes(input);
            Stopwatch stopwatch = new Stopwatch();

            using (System.Security.Cryptography.SHA256 algorithm = System.Security.Cryptography.SHA256.Create())
            {
                stopwatch.Restart();
                for (int i = 0; i < 10000; i++)
                {
                    algorithm.ComputeHash(input);
                }
                stopwatch.Stop();
                Console.WriteLine(".NET SHA256 Compute source 13KiB 10000 times : " + stopwatch.ElapsedMilliseconds + " milliseconds");
            }
            //
            {
                SHA256 algorithm = new SHA256();
                stopwatch.Restart();
                for (int i = 0; i < 10000; i++)
                {
                    algorithm.ComputeHash(input);
                }
                stopwatch.Stop();
                Console.WriteLine("BouncyCastle SHA256 Compute source 13KiB 10000 times : " + stopwatch.ElapsedMilliseconds + " milliseconds");
            }

            Console.ReadKey(true);
        }
    }
}