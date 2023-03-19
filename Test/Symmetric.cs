using Honoo.BouncyCastle;
using System;
using System.Linq;

namespace Test
{
    internal static class Symmetric
    {
        private static readonly byte[] _input = new byte[15];
        private static int _diff = 0;
        private static int _ignore = 0;
        private static int _total = 0;

        static Symmetric()
        {
            Common.SecureRandom.NextBytes(_input);
        }

        internal static void Test()
        {
            _total = 0;
            _diff = 0;
            _ignore = 0;
            Demo1();
            Demo2();
            DoNET();
            DoBlock();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine($"Total= {_total}  Diff= {_diff}  Ignore= {_ignore}");
            Console.ReadKey(true);
        }

        private static void Demo1()
        {
            AES alg1 = new AES { Mode = SymmetricCipherMode.CTR, Padding = SymmetricPaddingMode.TBC };
            AES alg2 = new AES { Mode = SymmetricCipherMode.CTR, Padding = SymmetricPaddingMode.TBC };
            byte[] key = new byte[16];
            byte[] iv = new byte[16];
            Common.SecureRandom.NextBytes(key);
            Common.SecureRandom.NextBytes(iv);
            alg1.ImportParameters(key, iv);
            alg2.ImportParameters(key, iv);
            byte[] enc = alg1.EncryptFinal(_input);
            byte[] dec = alg2.DecryptFinal(enc);
            _total++;
            WriteResult("Demo1", _input, enc, dec);
        }

        private static void Demo2()
        {
            AES alg1 = new AES { Mode = SymmetricCipherMode.EAX, Padding = SymmetricPaddingMode.NoPadding };
            AES alg2 = new AES { Mode = SymmetricCipherMode.EAX, Padding = SymmetricPaddingMode.NoPadding };
            byte[] key = new byte[16];
            byte[] nonce = new byte[22];
            Common.SecureRandom.NextBytes(key);
            Common.SecureRandom.NextBytes(nonce);
            alg1.ImportParameters(key, nonce, 64, new byte[] { 0x01, 0x02, 0x03 });
            alg2.ImportParameters(key, nonce, 64, new byte[] { 0x01, 0x02, 0x03 });
            byte[] enc = alg1.EncryptFinal(_input);
            byte[] dec = alg2.DecryptFinal(enc);
            _total++;
            WriteResult("Demo2", _input, enc, dec);
        }

        private static void DoBlock()
        {
            var modes = (SymmetricCipherMode[])Enum.GetValues(typeof(SymmetricCipherMode));
            var paddings = (SymmetricPaddingMode[])Enum.GetValues(typeof(SymmetricPaddingMode));
            foreach (var algorithmName in SymmetricAlgorithmName.GetNames())
            {
                if (algorithmName.Kind == SymmetricAlgorithmKind.Block)
                {
                    foreach (var mode in modes)
                    {
                        SymmetricBlockAlgorithm alg1 = SymmetricBlockAlgorithm.Create(algorithmName);
                        SymmetricBlockAlgorithm alg2 = SymmetricBlockAlgorithm.Create(algorithmName);
                        switch (mode)
                        {
                            case SymmetricCipherMode.GOFB: if (alg1.BlockSize != 64) continue; break;
                            case SymmetricCipherMode.SIC:
                            case SymmetricCipherMode.CCM:
                            case SymmetricCipherMode.EAX:
                            case SymmetricCipherMode.GCM:
                            case SymmetricCipherMode.OCB: if (alg1.BlockSize != 128) continue; break;
                            default: break;
                        }
                        foreach (var padding in paddings)
                        {
                            byte[] input = _input;
                            if (padding == SymmetricPaddingMode.NoPadding)
                            {
                                switch (mode)
                                {
                                    case SymmetricCipherMode.CCM:
                                    case SymmetricCipherMode.EAX:
                                    case SymmetricCipherMode.GCM:
                                    case SymmetricCipherMode.OCB:
                                        input = new byte[alg1.BlockSize / 4];
                                        Common.SecureRandom.NextBytes(input);
                                        break;

                                    default: break;
                                }
                                input = new byte[alg1.BlockSize / 4];
                                Common.SecureRandom.NextBytes(input);
                            }
                            else
                            {
                                switch (mode)
                                {
                                    case SymmetricCipherMode.CTS:
                                    case SymmetricCipherMode.CTS_ECB:
                                    case SymmetricCipherMode.CCM:
                                    case SymmetricCipherMode.EAX:
                                    case SymmetricCipherMode.GCM:
                                    case SymmetricCipherMode.OCB: continue;
                                    default: break;
                                }
                            }
                            _total++;
                            alg1.Mode = mode;
                            alg1.Padding = padding;
                            alg1.GenerateParameters();
                            alg1.ExportParameters(out byte[] key, out byte[] iv);
                            alg2.Mode = mode;
                            alg2.Padding = padding;
                            alg2.ImportParameters(key, iv);
                            alg1.EncryptFinal(input);
                            byte[] enc = alg1.EncryptFinal(input);
                            alg2.DecryptFinal(enc);
                            byte[] dec = alg2.DecryptFinal(enc);
                            string title = $"{algorithmName.Name}/{mode}/{padding}";
                            WriteResult(title.ToString(), input, enc, dec);
                        }
                    }
                }
            }
        }

        private static void DoNET()
        {
            var net = System.Security.Cryptography.Aes.Create();
            AES alg1 = new AES();
            AES alg2 = new AES();
            alg1.ImportParameters(net.Key, net.IV);
            alg2.ImportParameters(net.Key, net.IV);
            {
                _total++;
                byte[] enc = alg1.EncryptFinal(_input);
                byte[] dec;
                using (var decryptor = net.CreateDecryptor())
                {
                    dec = decryptor.TransformFinalBlock(enc, 0, enc.Length);
                }
                WriteResult("AES BouncyCastle <--> .NET", _input, enc, dec);
            }
            {
                _total++;
                byte[] enc;
                byte[] dec;
                using (var encryptor = net.CreateEncryptor())
                {
                    enc = encryptor.TransformFinalBlock(_input, 0, _input.Length);
                }
                dec = alg2.DecryptFinal(enc);
                WriteResult("AES BouncyCastle <--> .NET", _input, enc, dec);
            }
        }

        private static void WriteResult(string title, byte[] input, byte[] enc, byte[] dec)
        {
            string message = (title + " ").PadRight(40, '-');
            if (dec.SequenceEqual(input))
            {
                Console.WriteLine($"{message} same");
            }
            else
            {
                Console.WriteLine($"{message} diff <--");
                Console.WriteLine($"  org   {BitConverter.ToString(input).Replace('-', char.MinValue)}");
                Console.WriteLine($"  enc   {BitConverter.ToString(enc).Replace('-', char.MinValue)}");
                Console.WriteLine($"  dec   {BitConverter.ToString(dec).Replace('-', char.MinValue)}");
                _diff++;
            }
        }
    }
}