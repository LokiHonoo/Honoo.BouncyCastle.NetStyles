﻿using System;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Symmetric algorithm name.
    /// </summary>
    public sealed class SymmetricAlgorithmName : IEquatable<SymmetricAlgorithmName>
    {
        #region Delegate

        internal delegate SymmetricAlgorithm GetAlgorithmCallback();

        #endregion Delegate

        #region Block Algorithm Names

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static SymmetricAlgorithmName AES { get; } = Honoo.BouncyCastle.NetStyles.AES.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static SymmetricAlgorithmName Blowfish { get; } = Honoo.BouncyCastle.NetStyles.Blowfish.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static SymmetricAlgorithmName Camellia { get; } = Honoo.BouncyCastle.NetStyles.Camellia.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 64 bits. Legal key size 40-128 bits (8 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName CAST5 { get; } = Honoo.BouncyCastle.NetStyles.CAST5.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 128-256 bits (8 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName CAST6 { get; } = Honoo.BouncyCastle.NetStyles.CAST6.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 64 bits. Legal key size 64 bits.
        /// </summary>
        public static SymmetricAlgorithmName DES { get; } = Honoo.BouncyCastle.NetStyles.DES.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 64 bits. Legal key size 128, 192 bits.
        /// </summary>
        public static SymmetricAlgorithmName DESede { get; } = Honoo.BouncyCastle.NetStyles.DESede.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 128, 256 bits.
        /// </summary>
        public static SymmetricAlgorithmName DSTU7624_128 { get; } = DSTU7624.GetAlgorithmName(128);

        /// <summary>
        /// Symmetric block algorithm. Block size 256 bits. Legal key size 256, 512 bits.
        /// </summary>
        public static SymmetricAlgorithmName DSTU7624_256 { get; } = DSTU7624.GetAlgorithmName(256);

        /// <summary>
        /// Symmetric block algorithm. Block size 512 bits. Legal key size 512 bits.
        /// </summary>
        public static SymmetricAlgorithmName DSTU7624_512 { get; } = DSTU7624.GetAlgorithmName(512);

        /// <summary>
        /// Symmetric block algorithm. Block size 64 bits. Legal key size 256 bits.
        /// </summary>
        public static SymmetricAlgorithmName GOST28147 { get; } = Honoo.BouncyCastle.NetStyles.GOST28147.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 64 bits. Legal key size 8-128 bits (8 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName IDEA { get; } = Honoo.BouncyCastle.NetStyles.IDEA.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static SymmetricAlgorithmName Noekeon { get; } = Honoo.BouncyCastle.NetStyles.Noekeon.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 64 bits. Legal key size 8-1024 bits (8 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName RC2 { get; } = Honoo.BouncyCastle.NetStyles.RC2.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 64 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName RC5 { get; } = RC5_32.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName RC5_64 { get; } = Honoo.BouncyCastle.NetStyles.RC5_64.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName RC6 { get; } = Honoo.BouncyCastle.NetStyles.RC6.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static SymmetricAlgorithmName Rijndael128 { get; } = Rijndael.GetAlgorithmName(128);

        /// <summary>
        /// Symmetric block algorithm. Block size 160 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static SymmetricAlgorithmName Rijndael160 { get; } = Rijndael.GetAlgorithmName(160);

        /// <summary>
        /// Symmetric block algorithm. Block size 192 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static SymmetricAlgorithmName Rijndael192 { get; } = Rijndael.GetAlgorithmName(192);

        /// <summary>
        /// Symmetric block algorithm. Block size 224 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static SymmetricAlgorithmName Rijndael224 { get; } = Rijndael.GetAlgorithmName(224);

        /// <summary>
        /// Symmetric block algorithm. Block size 256 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static SymmetricAlgorithmName Rijndael256 { get; } = Rijndael.GetAlgorithmName(256);

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static SymmetricAlgorithmName SEED { get; } = Honoo.BouncyCastle.NetStyles.SEED.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName Serpent { get; } = Honoo.BouncyCastle.NetStyles.Serpent.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static SymmetricAlgorithmName SKIPJACK { get; } = Honoo.BouncyCastle.NetStyles.SKIPJACK.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static SymmetricAlgorithmName SM4 { get; } = Honoo.BouncyCastle.NetStyles.SM4.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static SymmetricAlgorithmName TEA { get; } = Honoo.BouncyCastle.NetStyles.TEA.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 1024 bits. Legal key size 1024 bits.
        /// </summary>
        public static SymmetricAlgorithmName Threefish1024 { get; } = Threefish.GetAlgorithmName(1024);

        /// <summary>
        /// Symmetric block algorithm. Block size 256 bits. Legal key size 256 bits.
        /// </summary>
        public static SymmetricAlgorithmName Threefish256 { get; } = Threefish.GetAlgorithmName(256);

        /// <summary>
        /// Symmetric block algorithm. Block size 512 bits. Legal key size 512 bits.
        /// </summary>
        public static SymmetricAlgorithmName Threefish512 { get; } = Threefish.GetAlgorithmName(512);

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName Tnepres { get; } = Honoo.BouncyCastle.NetStyles.Tnepres.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static SymmetricAlgorithmName Twofish { get; } = Honoo.BouncyCastle.NetStyles.Twofish.GetAlgorithmName();

        /// <summary>
        /// Symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static SymmetricAlgorithmName XTEA { get; } = Honoo.BouncyCastle.NetStyles.XTEA.GetAlgorithmName();

        #endregion Block Algorithm Names

        #region Stream Algorithm Names

        /// <summary>
        /// ymmetric stream algorithm. Legal key size 128, 256 bits. Legal iv size 64 bits.
        /// </summary>
        public static SymmetricAlgorithmName ChaCha { get; } = Honoo.BouncyCastle.NetStyles.ChaCha.GetAlgorithmName();

        /// <summary>
        /// ymmetric stream algorithm. Legal key size 256 bits. Legal iv size 96 bits.
        /// </summary>
        public static SymmetricAlgorithmName ChaCha7539 { get; } = Honoo.BouncyCastle.NetStyles.ChaCha7539.GetAlgorithmName();

        /// <summary>
        /// ymmetric stream algorithm. Legal key size 128 bits. Legal iv size 0-128 bits (8 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName HC128 { get; } = Honoo.BouncyCastle.NetStyles.HC128.GetAlgorithmName();

        /// <summary>
        /// ymmetric stream algorithm. Legal key size 128, 256 bits. Legal iv size 128-256 bits (8 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName HC256 { get; } = Honoo.BouncyCastle.NetStyles.HC256.GetAlgorithmName();

        /// <summary>
        /// ymmetric stream algorithm. Legal key size 64-8192 bits (16 bits increments). Not need iv.
        /// </summary>
        public static SymmetricAlgorithmName ISAAC { get; } = Honoo.BouncyCastle.NetStyles.ISAAC.GetAlgorithmName();

        /// <summary>
        /// ymmetric stream algorithm. Legal key size 256 bits. Not need iv.
        /// </summary>
        public static SymmetricAlgorithmName RC4 { get; } = Honoo.BouncyCastle.NetStyles.RC4.GetAlgorithmName();

        /// <summary>
        /// ymmetric stream algorithm. Legal key size 128, 256 bits. Legal iv size 64 bits.
        /// </summary>
        public static SymmetricAlgorithmName Salsa20 { get; } = Honoo.BouncyCastle.NetStyles.Salsa20.GetAlgorithmName();

        /// <summary>
        /// ymmetric stream algorithm. Legal key size 256 bits. Legal iv size 8-6144 bits (8 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName VMPC { get; } = Honoo.BouncyCastle.NetStyles.VMPC.GetAlgorithmName();

        /// <summary>
        /// ymmetric stream algorithm. Legal key size 256 bits. Legal iv size 8-6144 bits (8 bits increments).
        /// </summary>
        public static SymmetricAlgorithmName VMPC_KSA3 { get; } = Honoo.BouncyCastle.NetStyles.VMPC_KSA3.GetAlgorithmName();

        /// <summary>
        /// ymmetric stream algorithm. Legal key size 256 bits. Legal iv size 192 bits.
        /// </summary>
        public static SymmetricAlgorithmName XSalsa20 { get; } = Honoo.BouncyCastle.NetStyles.XSalsa20.GetAlgorithmName();

        #endregion Stream Algorithm Names

        #region Properties

        private readonly int _blockSize;
        private readonly GetAlgorithmCallback _getAlgorithm;
        private readonly SymmetricAlgorithmKind _kind;
        private readonly string _name;

        /// <summary>
        /// Gets block size bits. The value will be 0 if the algorithm is a stream algorithm.
        /// </summary>
        public int BlockSize => _blockSize;

        /// <summary>
        /// Gets algorithm kind of the algorithm.
        /// </summary>
        public SymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets this algorithm's name.
        /// </summary>
        public string Name => _name;

        internal GetAlgorithmCallback GetAlgorithm => _getAlgorithm;

        #endregion Properties

        #region Construction

        internal SymmetricAlgorithmName(string name, SymmetricAlgorithmKind kind, int blockSize, GetAlgorithmCallback getAlgorithm)
        {
            _name = name;
            _kind = kind;
            _blockSize = blockSize;
            _getAlgorithm = getAlgorithm;
        }

        #endregion Construction

        /// <summary>
        /// Gets all algorithm names of the storage.
        /// </summary>
        /// <returns></returns>
        public static SymmetricAlgorithmName[] GetNames()
        {
            return new SymmetricAlgorithmName[]
            {
                AES,
                Blowfish,
                Camellia,
                CAST5,
                CAST6,
                DES,
                DESede,
                DSTU7624_128,
                DSTU7624_256,
                DSTU7624_512,
                GOST28147,
                IDEA,
                Noekeon,
                RC2,
                RC5,
                RC5_64,
                RC6,
                Rijndael128,
                Rijndael160,
                Rijndael192,
                Rijndael224,
                Rijndael256,
                SEED,
                Serpent,
                SKIPJACK,
                SM4,
                TEA,
                Threefish256,
                Threefish512,
                Threefish1024,
                Tnepres,
                Twofish,
                XTEA,

                ChaCha,
                ChaCha7539,
                HC128,
                HC256,
                ISAAC,
                RC4,
                Salsa20,
                VMPC,
                VMPC_KSA3,
                XSalsa20,
            };
        }

        /// <summary>
        /// Gets algorithm names of the storage of the specified kind.
        /// </summary>
        /// <param name="kind">Algorithm kind.</param>
        /// <returns></returns>
        public static SymmetricAlgorithmName[] GetNames(SymmetricAlgorithmKind kind)
        {
            switch (kind)
            {
                case SymmetricAlgorithmKind.Block:
                    return new SymmetricAlgorithmName[]
                    {
                        AES,
                        Blowfish,
                        Camellia,
                        CAST5,
                        CAST6,
                        DES,
                        DESede,
                        DSTU7624_128,
                        DSTU7624_256,
                        DSTU7624_512,
                        GOST28147,
                        IDEA,
                        Noekeon,
                        RC2,
                        RC5,
                        RC5_64,
                        RC6,
                        Rijndael128,
                        Rijndael160,
                        Rijndael192,
                        Rijndael224,
                        Rijndael256,
                        SEED,
                        Serpent,
                        SKIPJACK,
                        SM4,
                        TEA,
                        Threefish256,
                        Threefish512,
                        Threefish1024,
                        Tnepres,
                        Twofish,
                        XTEA,
                    };

                case SymmetricAlgorithmKind.Stream:
                    return new SymmetricAlgorithmName[]
                    {
                        ChaCha,
                        ChaCha7539,
                        HC128,
                        HC256,
                        ISAAC,
                        RC4,
                        Salsa20,
                        VMPC,
                        VMPC_KSA3,
                        XSalsa20,
                    };

                default: return GetNames();
            }
        }

        /// <summary>
        /// Try get algorithm name from mechanism.
        /// </summary>
        /// <param name="mechanism">Algorithm mechanism.</param>
        /// <param name="algorithmName">Algorithm name.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithmName(string mechanism, out SymmetricAlgorithmName algorithmName)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithmName = null;
                return false;
            }
            mechanism = mechanism.Trim().Replace('_', '-').Replace('/', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "AES": algorithmName = AES; return true;
                case "BLOWFISH": algorithmName = Blowfish; return true;
                case "CAMELLIA": algorithmName = Camellia; return true;
                case "CAST5": algorithmName = CAST5; return true;
                case "CAST6": algorithmName = CAST6; return true;
                case "DES": algorithmName = DES; return true;
                case "DESEDE": case "DESEDE3": case "TDEA": case "TRIPLEDES": case "3DES": algorithmName = DESede; return true;
                case "DSTU7624-128": algorithmName = DSTU7624_128; return true;
                case "DSTU7624-256": algorithmName = DSTU7624_256; return true;
                case "DSTU7624-512": algorithmName = DSTU7624_512; return true;
                case "GOST28147": algorithmName = GOST28147; return true;
                case "IDEA": algorithmName = IDEA; return true;
                case "NOEKEON": algorithmName = Noekeon; return true;
                case "RC2": algorithmName = RC2; return true;
                case "RC5": case "RC532": algorithmName = RC5; return true;
                case "RC5-64": algorithmName = RC5_64; return true;
                case "RC6": algorithmName = RC6; return true;
                case "RIJNDAEL128": case "RIJNDAEL-128": case "RIJNDAEL": algorithmName = Rijndael128; return true;
                case "RIJNDAEL160": case "RIJNDAEL-160": algorithmName = Rijndael160; return true;
                case "RIJNDAEL192": case "RIJNDAEL-192": algorithmName = Rijndael192; return true;
                case "RIJNDAEL224": case "RIJNDAEL-224": algorithmName = Rijndael224; return true;
                case "RIJNDAEL256": case "RIJNDAEL-256": algorithmName = Rijndael256; return true;
                case "SEED": algorithmName = SEED; return true;
                case "SERPENT": algorithmName = Serpent; return true;
                case "SKIPJACK": algorithmName = SKIPJACK; return true;
                case "SM4": algorithmName = SM4; return true;
                case "TEA": algorithmName = TEA; return true;
                case "THREEFISH256": case "THREEFISH-256": case "THREEFISH": algorithmName = Threefish256; return true;
                case "THREEFISH512": case "THREEFISH-512": algorithmName = Threefish512; return true;
                case "THREEFISH1024": case "THREEFISH-1024": algorithmName = Threefish1024; return true;
                case "TNEPRES": algorithmName = Tnepres; return true;
                case "TWOFISH": algorithmName = Twofish; return true;
                case "XTEA": algorithmName = XTEA; return true;

                case "CHACHA": algorithmName = ChaCha; return true;
                case "CHACHA7539": case "CHACHA20": algorithmName = ChaCha7539; return true;
                case "HC128": case "HC-128": algorithmName = HC128; return true;
                case "HC256": case "HC-256": algorithmName = HC256; return true;
                case "ISAAC": algorithmName = ISAAC; return true;
                case "RC4": case "ARC4": case "ARCFOUR": algorithmName = RC4; return true;
                case "SALSA20": algorithmName = Salsa20; return true;
                case "VMPC": algorithmName = VMPC; return true;
                case "VMPC-KSA3": case "VMPCKSA3": algorithmName = VMPC_KSA3; return true;
                case "XSALSA20": algorithmName = XSalsa20; return true;
                default: algorithmName = null; return false;
            }
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(SymmetricAlgorithmName other)
        {
            return other._name.Equals(_name);
        }

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }
    }
}