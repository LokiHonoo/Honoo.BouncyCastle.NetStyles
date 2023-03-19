using Honoo.BouncyCastle;
using System;
using System.Linq;

namespace Test
{
    internal static class Hash
    {
        private static readonly byte[] _input = new byte[15];
        private static int _diff = 0;
        private static int _ignore = 0;
        private static int _total = 0;

        static Hash()
        {
            Common.SecureRandom.NextBytes(_input);
        }

        internal static void Test()
        {
            _total = 0;
            _diff = 0;
            _ignore = 0;
            Demo();
            DoAll();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine($"Total= {_total}  Diff= {_diff}  Ignore= {_ignore}");
            Console.ReadKey(true);
        }

        private static void Demo()
        {
            SHA1 sha1 = new SHA1();
            _ = sha1.ComputeHash(_input);
        }

        private static void DoAll()
        {
            foreach (var algorithmName in HashAlgorithmName.GetNames())
            {
                _total++;
                HashAlgorithm alg = HashAlgorithm.Create(algorithmName);
                alg.ComputeHash(_input);
                byte[] hash1 = alg.ComputeHash(_input);
                var net = System.Security.Cryptography.HashAlgorithm.Create(algorithmName.Name);
                byte[] hash2 = net == null ? hash1 : net.ComputeHash(_input);
                string title = $"{algorithmName.Name}/{algorithmName.HashSize}";
                WriteResult(title.ToString(), hash1, hash2);
            }
            string[] mechanisms = new string[] { "BLAKE2b128", "BLAKE2s128", "SHA512/376", "SHA512/392", "SHA512T504", "Skein224-512" };
            foreach (var mechanism in mechanisms)
            {
                _total++;
                HashAlgorithmName.TryGetAlgorithmName(mechanism, out HashAlgorithmName algorithmName);
                HashAlgorithm alg = HashAlgorithm.Create(algorithmName);
                alg.ComputeHash(_input);
                byte[] hash1 = alg.ComputeHash(_input);
                var net = System.Security.Cryptography.HashAlgorithm.Create(algorithmName.Name);
                byte[] hash2 = net == null ? hash1 : net.ComputeHash(_input);
                string title = $"{algorithmName.Name}/{algorithmName.HashSize}";
                WriteResult(title.ToString(), hash1, hash2);
            }
        }

        private static void WriteResult(string title, byte[] hash1, byte[] hash2)
        {
            string message = (title + " ").PadRight(20, '-');
            if (hash2.SequenceEqual(hash1))
            {
                Console.WriteLine($"{message} same");
            }
            else
            {
                Console.WriteLine($"{message} diff <--");
                Console.WriteLine($"  hash1   {BitConverter.ToString(hash1).Replace('-', char.MinValue)}");
                Console.WriteLine($"  hash2   {BitConverter.ToString(hash2).Replace('-', char.MinValue)}");
                _diff++;
            }
        }
    }
}