using Honoo.BouncyCastle;
using System;
using System.Collections.Generic;
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
            HMAC hmac1 = HMAC.Create(HashAlgorithmName.BLAKE2b256);
            hmac1.GenerateParameters(224); // Any length.
            hmac1.ExportParameters(out byte[] key);
            _ = hmac1.ComputeHash(_input);
            HMAC hmac2 = HMAC.Create(HashAlgorithmName.BLAKE2b256);
            hmac2.ImportParameters(key);
            _ = hmac2.ComputeHash(_input);
        }

        private static void Demo3()
        {
            CMAC cmac1 = CMAC.Create(SymmetricAlgorithmName.AES);
            // 192 = AES legal key size bits.
            cmac1.GenerateParameters(192);
            cmac1.ExportParameters(out byte[] key);
            _ = cmac1.ComputeHash(_input);
            CMAC cmac2 = CMAC.Create(SymmetricAlgorithmName.AES);
            cmac2.ImportParameters(key);
            _ = cmac2.ComputeHash(_input);
        }

        private static void Demo4()
        {
            MAC mac1 = MAC.Create(SymmetricAlgorithmName.Rijndael224);
            mac1.Mode = SymmetricCipherMode.CBC;
            mac1.Padding = SymmetricPaddingMode.TBC;
            // 160 = Rijndael legal key size bits.
            // 224 = CBC mode limit same as Rijndael block size bits.
            mac1.GenerateParameters(160, 224);
            mac1.ExportParameters(out byte[] key, out byte[] iv);
            _ = mac1.ComputeHash(_input);
            MAC mac2 = MAC.Create(SymmetricAlgorithmName.Rijndael224);
            mac2.ImportParameters(key, iv);
            _ = mac2.ComputeHash(_input);
        }

        private static void DoAll()
        {
            var algorithmNames = new List<HashAlgorithmName>(HashAlgorithmName.GetNames());
            string[] mechanisms = new string[] { "BLAKE2b128", "BLAKE2s128", "SHA512/376", "SHA512/392", "SHA512T504", "Skein224-512" };
            foreach (var mechanism in mechanisms)
            {
                HashAlgorithmName.TryGetAlgorithmName(mechanism, out HashAlgorithmName algorithmName);
                algorithmNames.Add(algorithmName);
            }
            foreach (var algorithmName in algorithmNames)
            {
                if (algorithmName.Name.StartsWith("Skein"))
                {
                }
                _total++;
                HashAlgorithmName.TryGetAlgorithmName(algorithmName.Name, out HashAlgorithmName algorithmName2);
                HashAlgorithm alg = HashAlgorithm.Create(algorithmName2);
                string title = $"{alg.Name}/{alg.HashSize}";
                alg.ComputeHash(_input);
                var net = System.Security.Cryptography.HashAlgorithm.Create(algorithmName2.Name);
                byte[] hash = net == null ? alg.ComputeHash(_input) : net.ComputeHash(_input);
                WriteResult(title, hash, alg.ComputeHash(_input));
            }
            foreach (var algorithmName in algorithmNames)
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
                Console.WriteLine($"{message} diff");
                Console.WriteLine($"  hash1   {BitConverter.ToString(hash1).Replace('-', char.MinValue)}");
                Console.WriteLine($"  hash2   {BitConverter.ToString(hash2).Replace('-', char.MinValue)}");
                _diff++;
            }
        }
    }
}