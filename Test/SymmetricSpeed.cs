using Honoo.BouncyCastle;
using System;
using System.Diagnostics;

namespace Test
{
    internal static class SymmetricSpeed
    {
        internal static void Test()
        {
            byte[] input = new byte[64000];
            Common.Random.NextBytes(input);
            Stopwatch stopwatch = new Stopwatch();
            byte[] key = new byte[128 / 8];
            Common.Random.NextBytes(key);
            byte[] iv = new byte[128 / 8];
            Common.Random.NextBytes(iv);
            using (System.Security.Cryptography.Aes algorithm = System.Security.Cryptography.Aes.Create())
            {
                using (System.Security.Cryptography.ICryptoTransform encryptor = algorithm.CreateEncryptor(key, iv),
                    decryptor = algorithm.CreateDecryptor(key, iv))
                {
                    stopwatch.Restart();
                    for (int i = 0; i < 10000; i++)
                    {
                        byte[] enc = encryptor.TransformFinalBlock(input, 0, input.Length);
                        _ = decryptor.TransformFinalBlock(enc, 0, enc.Length);
                    }
                    stopwatch.Stop();
                }

                Console.WriteLine(".NET AES Enc/Dec source 64KiB 10000 times : " + stopwatch.ElapsedMilliseconds + " milliseconds");
            }
            //
            {
                AES algorithm = new AES();
                algorithm.ImportParameters(key, iv);
                stopwatch.Restart();
                for (int i = 0; i < 10000; i++)
                {
                    byte[] enc = algorithm.EncryptFinal(input);
                    _ = algorithm.DecryptFinal(enc);
                }
                stopwatch.Stop();
                Console.WriteLine("BouncyCastle AES Enc/Dec source 64KiB 10000 times : " + stopwatch.ElapsedMilliseconds + " milliseconds");
            }
            Console.ReadKey(true);
        }
    }
}