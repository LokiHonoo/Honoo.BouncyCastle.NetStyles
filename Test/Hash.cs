using Honoo.BouncyCastle.NetStyles;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Test
{
    internal static class Hash
    {
        private static readonly byte[] _input = new byte[15];
        private static readonly byte[] _keyExchangePms = new byte[300];
        private static int _diff = 0;
        private static int _ignore = 0;
        private static int _total = 0;

        static Hash()
        {
            Common.Random.NextBytes(_input);
            Common.Random.NextBytes(_keyExchangePms);
        }

        internal static void Test()
        {
            _total = 0;
            _diff = 0;
            _ignore = 0;
            DoLength();
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
            _ = sha1.ComputeFinal(_input);

            HashAlgorithm sha256 = HashAlgorithm.Create(HashAlgorithmName.SHA256);
            sha256.Update(_input);
            _ = sha256.ComputeFinal();
        }

        private static void Demo2()
        {
            HMAC hmac1 = HMAC.Create(HMACName.HMAC_SM3);
            byte[] key = new byte[66]; // Any length.
            Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
            hmac1.ImportParameters(key);
            _ = hmac1.ComputeFinal(_input);
            HMAC hmac2 = HMAC.Create(HMACName.HMAC_SM3);
            hmac2.ImportParameters(key);
            _ = hmac2.ComputeFinal(_input);
        }

        private static void Demo3()
        {
            CMAC cmac1 = CMAC.Create(CMACName.AES_CMAC);
            byte[] key = new byte[192 / 8]; // 192 = AES legal key size bits.
            Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
            cmac1.ImportParameters(key);
            _ = cmac1.ComputeFinal(_input);
            CMAC cmac2 = CMAC.Create(CMACName.AES_CMAC);
            cmac2.ImportParameters(key);
            _ = cmac2.ComputeFinal(_input);
        }

        private static void Demo4()
        {
            MAC mac1 = MAC.Create(MACName.Rijndael224_MAC);
            mac1.Mode = SymmetricCipherMode.CBC;
            mac1.Padding = SymmetricPaddingMode.TBC;
            byte[] key = new byte[160 / 8];  // 160 = Rijndael legal key size bits.
            byte[] iv = new byte[224 / 8];   // 224 = CBC mode limit same as Rijndael block size bits.
            Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
            Buffer.BlockCopy(_keyExchangePms, 0, iv, 0, iv.Length);
            mac1.ImportParameters(key, iv);
            _ = mac1.ComputeFinal(_input);
            MAC mac2 = MAC.Create(MACName.Rijndael224_MAC);
            mac2.ImportParameters(key, iv);
            _ = mac2.ComputeFinal(_input);
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
                _total++;
                HashAlgorithmName.TryGetAlgorithmName(algorithmName.Name, out HashAlgorithmName algorithmName2);
                HashAlgorithm alg = HashAlgorithm.Create(algorithmName2);
                alg.ComputeFinal(_input);
                var net = System.Security.Cryptography.HashAlgorithm.Create(algorithmName2.Name);
                byte[] hash = net == null ? alg.ComputeFinal(_input) : net.ComputeHash(_input);
                WriteResult(alg.Name, alg.HashSize, hash, alg.ComputeFinal(_input));
            }
            foreach (var algorithmName in HMACName.GetNames())
            {
                _total++;
                HMACName.TryGetAlgorithmName(algorithmName.Name, out HMACName algorithmName2);
                HMAC alg = HMAC.Create(algorithmName2);
                alg.GenerateParameters(112);
                var param = alg.ExportParameters();
                alg.ImportParameters(param);
                alg.ComputeFinal(_input);
                var net = System.Security.Cryptography.HMAC.Create($"HMAC{algorithmName}");
                byte[] hash;
                if (net == null)
                {
                    hash = alg.ComputeFinal(_input); ;
                }
                else
                {
                    alg.ExportParameters(out byte[] key);
                    net.Key = key;
                    hash = net.ComputeHash(_input);
                }
                WriteResult(alg.Name, alg.HashSize, hash, alg.ComputeFinal(_input));
            }
            foreach (var algorithmName in CMACName.GetNames())
            {
                _total++;
                CMACName.TryGetAlgorithmName(algorithmName.Name, out CMACName algorithmName2);
                CMAC alg = CMAC.Create(algorithmName2, algorithmName.BlockSize / 2);
                alg.GenerateParameters();
                var param = alg.ExportParameters();
                alg.ImportParameters(param);
                alg.ComputeFinal(_input);
                WriteResult(alg.Name, alg.HashSize, alg.ComputeFinal(_input), alg.ComputeFinal(_input));
            }
            foreach (var algorithmName in MACName.GetNames())
            {
                _total++;
                MACName.TryGetAlgorithmName(algorithmName.Name, out MACName algorithmName2);
                MAC alg = MAC.Create(algorithmName2, algorithmName.BlockSize / 2);
                alg.GenerateParameters();
                var param = alg.ExportParameters();
                alg.ImportParameters(param);
                alg.ComputeFinal(_input);
                WriteResult(alg.Name, alg.HashSize, alg.ComputeFinal(_input), alg.ComputeFinal(_input));
            }
        }

        private static void DoLength()
        {
            foreach (var algorithmName in HashAlgorithmName.GetNames())
            {
                HashAlgorithm alg = HashAlgorithm.Create(algorithmName);
                byte[] hash = alg.ComputeFinal(_input);
                Console.WriteLine($"{alg.Name + " " + alg.HashSize,-24} {BitConverter.ToString(hash).Replace("-", "")}");
            }
        }

        private static void WriteResult(string title, int hashSize, byte[] hash1, byte[] hash2)
        {
            string message = $"{title,-20} HASHSIZE {hashSize}/{hash1.Length * 8} ".PadRight(50, '-');
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