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
            Common.Random.NextBytes(_input);
        }

        internal static void Test()
        {
            _total = 0;
            _diff = 0;
            _ignore = 0;
            Demo1();
            Demo2();
            Demo3();
            Demo4();
            DoAll();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine($"Total= {_total}  Diff= {_diff}  Ignore= {_ignore}");
            Console.ReadKey(true);
        }

        private static void Demo1()
        {
            SHA1 sha1 = new SHA1();
            _ = sha1.ComputeHash(_input);
        }

        private static void Demo2()
        {
            HMAC hmac = HMAC.Create(HashAlgorithmName.BLAKE2b256);
            hmac.GenerateParameters(224);
            _ = hmac.ComputeHash(_input);
        }

        private static void Demo3()
        {
            CMAC cmac = CMAC.Create(SymmetricAlgorithmName.AES);
            cmac.GenerateParameters(192);
            _ = cmac.ComputeHash(_input);
        }

        private static void Demo4()
        {
            MAC mac = MAC.Create(SymmetricAlgorithmName.Rijndael224);
            mac.Mode = SymmetricCipherMode.CBC;
            mac.Padding = SymmetricPaddingMode.TBC;
            mac.GenerateParameters(160, 224);
            _ = mac.ComputeHash(_input);
        }

        private static void DoAll()
        {
            foreach (var algorithmName in HashAlgorithmName.GetNames())
            {
                _total++;
                HashAlgorithm alg = HashAlgorithm.Create(algorithmName);
                string title = $"{alg.Name}/{alg.HashSize}";
                alg.ComputeHash(_input);
                var net = System.Security.Cryptography.HashAlgorithm.Create(algorithmName.Name);
                byte[] hash = net == null ? alg.ComputeHash(_input) : net.ComputeHash(_input);
                WriteResult(title, hash, alg.ComputeHash(_input));
            }
            string[] mechanisms = new string[] { "BLAKE2b128", "BLAKE2s128", "SHA512/376", "SHA512/392", "SHA512T504", "Skein224-512" };
            foreach (var mechanism in mechanisms)
            {
                _total++;
                HashAlgorithmName.TryGetAlgorithmName(mechanism, out HashAlgorithmName algorithmName);
                HashAlgorithm alg = HashAlgorithm.Create(algorithmName);
                string title = $"{alg.Name}/{alg.HashSize}";
                WriteResult(title, alg.ComputeHash(_input), alg.ComputeHash(_input));
            }
            foreach (var algorithmName in HashAlgorithmName.GetNames())
            {
                _total++;
                HMAC alg = HMAC.Create(algorithmName);
                string title = $"{alg.Name}/{alg.HashSize}";
                alg.GenerateParameters(112);
                alg.ComputeHash(_input);
                var net = System.Security.Cryptography.HMAC.Create($"HMAC{algorithmName}");
                byte[] hash;
                if (net == null)
                {
                    hash = alg.ComputeHash(_input); ;
                }
                else
                {
                    alg.ExportParameters(out byte[] key);
                    net.Key = key;
                    hash = net.ComputeHash(_input);
                }
                WriteResult(title, hash, alg.ComputeHash(_input));
            }
            foreach (var algorithmName in SymmetricAlgorithmName.GetNames())
            {
                if (algorithmName.Kind == SymmetricAlgorithmKind.Block && (algorithmName.BlockSize == 64 || algorithmName.BlockSize == 128))
                {
                    _total++;
                    CMAC alg = CMAC.Create(algorithmName, algorithmName.BlockSize / 2);
                    string title = $"{alg.Name}/{alg.HashSize}";
                    alg.GenerateParameters();
                    alg.ComputeHash(_input);
                    WriteResult(title, alg.ComputeHash(_input), alg.ComputeHash(_input));
                }
            }
            foreach (var algorithmName in SymmetricAlgorithmName.GetNames())
            {
                if (algorithmName.Kind == SymmetricAlgorithmKind.Block)
                {
                    _total++;
                    MAC alg = MAC.Create(algorithmName, algorithmName.BlockSize / 2);
                    string title = $"{alg.Name}/{alg.HashSize}";
                    alg.GenerateParameters();
                    alg.ComputeHash(_input);
                    WriteResult(title, alg.ComputeHash(_input), alg.ComputeHash(_input));
                }
            }
        }

        private static void WriteResult(string title, byte[] hash1, byte[] hash2)
        {
            string message = (title + " ").PadRight(32, '-');
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