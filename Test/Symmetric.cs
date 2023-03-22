﻿using Honoo.BouncyCastle;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Linq;

namespace Test
{
    internal static class Symmetric
    {
        private static readonly byte[] _input = new byte[123];
        private static int _diff = 0;
        private static int _ignore = 0;
        private static int _total = 0;

        static Symmetric()
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
            DoNET();
            DoAll();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine($"Total= {_total}  Diff= {_diff}  Ignore= {_ignore}");
            Console.ReadKey(true);
        }

        private static void Demo1()
        {
            SymmetricAlgorithm alg1 = SymmetricAlgorithm.Create(SymmetricAlgorithmName.Rijndael224);
            alg1.Mode = SymmetricCipherMode.CTR;
            alg1.Padding = SymmetricPaddingMode.TBC;
            Rijndael alg2 = new Rijndael(224) { Mode = SymmetricCipherMode.CTR, Padding = SymmetricPaddingMode.TBC };
            byte[] key = new byte[16];
            byte[] iv = new byte[28];
            Common.Random.NextBytes(key);
            Common.Random.NextBytes(iv);
            alg1.ImportParameters(key, iv);
            alg2.ImportParameters(key, iv);
            byte[] enc = alg1.EncryptFinal(_input);
            _ = alg2.DecryptFinal(enc);
        }

        private static void Demo2()
        {
            AES alg1 = (AES)SymmetricAlgorithm.Create(SymmetricAlgorithmName.AES);
            alg1.Mode = SymmetricCipherMode.EAX;
            alg1.Padding = SymmetricPaddingMode.NoPadding;
            AES alg2 = new AES { Mode = SymmetricCipherMode.EAX, Padding = SymmetricPaddingMode.NoPadding };
            byte[] key = new byte[16];
            byte[] nonce = new byte[22];
            Common.Random.NextBytes(key);
            Common.Random.NextBytes(nonce);
            alg1.ImportParameters(key, nonce, 64, new byte[] { 0x01, 0x02, 0x03 });
            alg2.ImportParameters(key, nonce, 64, new byte[] { 0x01, 0x02, 0x03 });
            byte[] enc = alg1.EncryptFinal(_input);
            _ = alg2.DecryptFinal(enc);
        }

        private static void Demo3()
        {
            SymmetricAlgorithm alg1 = SymmetricAlgorithm.Create(SymmetricAlgorithmName.HC128);
            HC128 alg2 = new HC128();
            byte[] key = new byte[16];
            byte[] iv = new byte[16];
            Common.Random.NextBytes(key);
            Common.Random.NextBytes(iv);
            alg1.ImportParameters(key, iv);
            alg2.ImportParameters(key, iv);
            byte[] enc = alg1.EncryptFinal(_input);
            _ = alg2.DecryptFinal(enc);
        }

        private static void DoAll()
        {
            var modes = (SymmetricCipherMode[])Enum.GetValues(typeof(SymmetricCipherMode));
            var paddings = (SymmetricPaddingMode[])Enum.GetValues(typeof(SymmetricPaddingMode));
            foreach (var algorithmName in SymmetricAlgorithmName.GetNames())
            {
                SymmetricAlgorithmName.TryGetAlgorithmName(algorithmName.Name, out SymmetricAlgorithmName algorithmName2);
                var alg1 = SymmetricAlgorithm.Create(algorithmName2);
                var alg2 = SymmetricAlgorithm.Create(algorithmName);
                if (algorithmName.Kind == SymmetricAlgorithmKind.Block)
                {
                    foreach (var mode in modes)
                    {
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
                                    case SymmetricCipherMode.CBC:
                                    case SymmetricCipherMode.ECB:
                                    case SymmetricCipherMode.OFB:
                                    case SymmetricCipherMode.CFB:
                                    case SymmetricCipherMode.CTS:
                                    case SymmetricCipherMode.CTR:
                                    case SymmetricCipherMode.CTS_ECB:
                                    case SymmetricCipherMode.GOFB:
                                    case SymmetricCipherMode.OpenPGPCFB:
                                    case SymmetricCipherMode.SIC:
                                        input = new byte[alg1.BlockSize / 4];
                                        Common.Random.NextBytes(input);
                                        break;

                                    default: break;
                                }
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
                            string title = $"{algorithmName.Name}/{mode}/{padding}";
                            alg1.Mode = mode;
                            alg1.Padding = padding;
                            alg1.GenerateParameters();
                            alg1.ExportParameters(out byte[] key, out byte[] iv);
                            alg1.EncryptFinal(input);
                            byte[] enc = alg1.EncryptFinal(input);
                            //
                            byte[] dec;
                            IBufferedCipher cipher = null;
                            try
                            {
                                cipher = Org.BouncyCastle.Security.CipherUtilities.GetCipher($"{alg1.Name}/{mode}/{padding}");
                            }
                            catch { }
                            if (cipher == null)
                            {
                                alg2.Mode = mode;
                                alg2.Padding = padding;
                                alg2.ImportParameters(key, iv);
                                alg2.DecryptFinal(enc);
                                dec = alg2.DecryptFinal(enc);
                            }
                            else
                            {
                                ICipherParameters para;
                                if (alg1.Name == "RC5" || alg1.Name == "RC5-64")
                                {
                                    para = new RC5Parameters(key, 12);
                                }
                                else
                                {
                                    para = new KeyParameter(key);
                                }
                                if (iv != null)
                                {
                                    para = new ParametersWithIV(para, iv);
                                }
                                cipher.Init(false, para);
                                dec = cipher.DoFinal(enc);
                            }

                            WriteResult(title, input, enc, dec);
                        }
                    }
                }
                else
                {
                    _total++;
                    alg1.GenerateParameters();
                    alg1.ExportParameters(out byte[] key, out byte[] iv);
                    alg2.ImportParameters(key, iv);
                    alg1.EncryptFinal(_input);
                    byte[] enc = alg1.EncryptFinal(_input);
                    alg2.DecryptFinal(enc);
                    byte[] dec = alg2.DecryptFinal(enc);
                    WriteResult(algorithmName.Name, _input, enc, dec);
                }
            }
        }

        private static void DoNET()
        {
            var names1 = new SymmetricAlgorithmName[]
            {
                SymmetricAlgorithmName.AES,
                SymmetricAlgorithmName.DESede
            };
            string[] names2 = new string[] { "AES", "3DES" };
            var modes1 = new SymmetricCipherMode[]
            {
               SymmetricCipherMode.CBC,
               SymmetricCipherMode.ECB,
               //SymmetricCipherMode.OFB,
               SymmetricCipherMode.CFB,
               //SymmetricCipherMode.CTS,
            };
            var modes2 = new System.Security.Cryptography.CipherMode[]
            {
               System.Security.Cryptography.CipherMode.CBC,
               System.Security.Cryptography.CipherMode.ECB,
               //System.Security.Cryptography.CipherMode.OFB,
               System.Security.Cryptography.CipherMode.CFB,
               //System.Security.Cryptography.CipherMode.CTS,
            };
            var paddings1 = new SymmetricPaddingMode[]
            {
                SymmetricPaddingMode.NoPadding,
                SymmetricPaddingMode.PKCS7,
                //SymmetricPaddingMode.Zeros,
                SymmetricPaddingMode.X923,
                SymmetricPaddingMode.ISO10126,
            };
            var paddings2 = new System.Security.Cryptography.PaddingMode[]
            {
                System.Security.Cryptography.PaddingMode.None,
                System.Security.Cryptography.PaddingMode.PKCS7,
                //System.Security.Cryptography.PaddingMode.Zeros,
                System.Security.Cryptography.PaddingMode.ANSIX923,
                System.Security.Cryptography.PaddingMode.ISO10126,
            };
            for (int i = 0; i < names1.Length; i++)
            {
                SymmetricAlgorithm alg = SymmetricAlgorithm.Create(names1[i]);
                var net = System.Security.Cryptography.SymmetricAlgorithm.Create(names2[i]);
                for (int j = 0; j < modes1.Length; j++)
                {
                    for (int k = 0; k < paddings1.Length; k++)
                    {
                        if (modes1[j] == SymmetricCipherMode.CTS && paddings1[k] != SymmetricPaddingMode.NoPadding)
                        {
                            continue;
                        }
                        byte[] input = _input;
                        if (paddings1[k] == SymmetricPaddingMode.NoPadding)
                        {
                            input = new byte[alg.BlockSize * 3];
                            Common.Random.NextBytes(input);
                        }
                        _total++;
                        string title = $"{alg.Name}/{modes1[j]}/{paddings1[k]}  BC <--> NET";
                        alg.Mode = modes1[j];
                        alg.Padding = paddings1[k];
                        alg.GenerateParameters();
                        alg.ExportParameters(out byte[] key, out byte[] iv);
                        net.Mode = modes2[j];
                        net.Padding = paddings2[k];
                        net.FeedbackSize = net.BlockSize;
                        net.Key = key;
                        net.IV = iv ?? (new byte[net.BlockSize / 8]);
                        alg.EncryptFinal(input);
                        byte[] enc = alg.EncryptFinal(input);
                        using (var decryptor = net.CreateDecryptor())
                        {
                            byte[] dec = decryptor.TransformFinalBlock(enc, 0, enc.Length);
                            WriteResult(title, input, enc, dec);
                        }
                    }
                }
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
                Console.WriteLine($"{message} diff");
                Console.WriteLine($"  org   {BitConverter.ToString(input).Replace('-', char.MinValue)}");
                Console.WriteLine($"  enc   {BitConverter.ToString(enc).Replace('-', char.MinValue)}");
                Console.WriteLine($"  dec   {BitConverter.ToString(dec).Replace('-', char.MinValue)}");
                _diff++;
            }
        }
    }
}