﻿using Org.BouncyCastle.Crypto;
using System;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Hash algorithm name.
    /// </summary>
    public sealed class HashAlgorithmName : IEquatable<HashAlgorithmName>
    {
        #region Delegate

        internal delegate HashAlgorithm GetAlgorithmCallback();

        internal delegate IDigest GetDigestCallback();

        #endregion Delegate

        #region AlgorithmNames

        /// <summary>
        /// SHA1 algorithm. Hash size 256 bits.
        /// </summary>
        public static HashAlgorithmName BLAKE2b256 { get; } = BLAKE2b.GetAlgorithmName(256);

        /// <summary>
        /// SHA1 algorithm. Hash size 384 bits.
        /// </summary>
        public static HashAlgorithmName BLAKE2b384 { get; } = BLAKE2b.GetAlgorithmName(384);

        /// <summary>
        /// SHA1 algorithm. Hash size 512 bits.
        /// </summary>
        public static HashAlgorithmName BLAKE2b512 { get; } = BLAKE2b.GetAlgorithmName(512);

        /// <summary>
        /// SHA1 algorithm. Hash size 256 bits.
        /// </summary>
        public static HashAlgorithmName BLAKE2s256 { get; } = BLAKE2s.GetAlgorithmName(256);

        /// <summary>
        /// SHA1 algorithm. Hash size 128 bits.
        /// </summary>
        public static HashAlgorithmName MD2 { get; } = Honoo.BouncyCastle.MD2.GetAlgorithmName();

        /// <summary>
        /// SHA1 algorithm. Hash size 160 bits.
        /// </summary>
        public static HashAlgorithmName SHA1 { get; } = Honoo.BouncyCastle.SHA1.GetAlgorithmName();

        /// <summary>
        /// SHA1 algorithm. Hash size 224 bits.
        /// </summary>
        public static HashAlgorithmName SHA224 { get; } = Honoo.BouncyCastle.SHA224.GetAlgorithmName();

        /// <summary>
        /// SHA1 algorithm. Hash size 256 bits.
        /// </summary>
        public static HashAlgorithmName SHA256 { get; } = Honoo.BouncyCastle.SHA256.GetAlgorithmName();

        /// <summary>
        /// SHA1 algorithm. Hash size 384 bits.
        /// </summary>
        public static HashAlgorithmName SHA384 { get; } = Honoo.BouncyCastle.SHA384.GetAlgorithmName();

        /// <summary>
        /// SHA1 algorithm. Hash size 512 bits.
        /// </summary>
        public static HashAlgorithmName SHA512 { get; } = Honoo.BouncyCastle.SHA512.GetAlgorithmName();

        /// <summary>
        /// SHA512/224 algorithm. Hash size 224 bits.
        /// </summary>
        public static HashAlgorithmName SHA512_224 { get; } = SHA512T.GetAlgorithmName(224);

        /// <summary>
        /// SHA512/256 algorithm. Hash size 256 bits.
        /// </summary>
        public static HashAlgorithmName SHA512_256 { get; } = SHA512T.GetAlgorithmName(256);

        /// <summary>
        /// Skein1024-1024 algorithm. Hash size 1024 bits.
        /// </summary>
        public static HashAlgorithmName Skein1024_1024 { get; } = Skein.GetAlgorithmName(1024, 1024);

        /// <summary>
        /// Skein256-256 algorithm. Hash size 256 bits.
        /// </summary>
        public static HashAlgorithmName Skein256_256 { get; } = Skein.GetAlgorithmName(256, 256);

        /// <summary>
        /// Skein512-512 algorithm. Hash size 512 bits.
        /// </summary>
        public static HashAlgorithmName Skein512_512 { get; } = Skein.GetAlgorithmName(512, 512);

        #endregion AlgorithmNames

        #region Properties

        private readonly GetAlgorithmCallback _getAlgorithm;
        private readonly GetDigestCallback _getDigest;
        private readonly int _hashSize;
        private readonly string _name;

        /// <summary>
        /// Gets hash size bits of the algorithm.
        /// </summary>
        public int HashSize => _hashSize;

        /// <summary>
        /// Gets this hash algorithm's name.
        /// </summary>
        public string Name => _name;

        internal GetAlgorithmCallback GetAlgorithm => _getAlgorithm;
        internal GetDigestCallback GetDigest => _getDigest;

        #endregion Properties

        #region Construction

        internal HashAlgorithmName(string name, int hashSize, GetDigestCallback getDigest, GetAlgorithmCallback getAlgorithm)
        {
            _name = name;
            _hashSize = hashSize;
            _getDigest = getDigest;
            _getAlgorithm = getAlgorithm;
        }

        #endregion Construction

        /// <summary>
        /// Gets all hash algorithm names.
        /// </summary>
        /// <returns></returns>
        public static HashAlgorithmName[] GetNames()
        {
            return new HashAlgorithmName[]
            {
                BLAKE2b256,
                BLAKE2b384,
                BLAKE2b512,
                BLAKE2s256,
                //CSHAKE_128,
                //CSHAKE_256,
                //DSTU7564_256,
                //DSTU7564_384,
                //DSTU7564_512,
                //GOST3411,
                //GOST3411_2012_256,
                //GOST3411_2012_512,
                //Keccak_128,
                //Keccak_224,
                //Keccak_256,
                //Keccak_288,
                //Keccak_384,
                //Keccak_512,
                MD2,
                //MD4,
                //MD5,
                //RIPEMD128,
                //RIPEMD160,
                //RIPEMD256,
                //RIPEMD320,
                SHA1,
                SHA224,
                SHA256,
                SHA384,
                SHA512,
                SHA512_224,
                SHA512_256,
                //SHA3_224,
                //SHA3_256,
                //SHA3_384,
                //SHA3_512,
                //SHAKE_128,
                //SHAKE_256,
                Skein256_256,
                Skein512_512,
                Skein1024_1024,
                //SM3,
                //Tiger,
                //Whirlpool,
            };
        }

        /// <summary>
        /// Try get hash algorithm name from mechanism.
        /// </summary>
        /// <param name="mechanism">Hash algorithm mechanism.</param>
        /// <param name="algorithmName">Hash algorithm name.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithmName(string mechanism, out HashAlgorithmName algorithmName)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithmName = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').Replace('/', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "BLAKE2B256": case "BLAKE2B-256": algorithmName = BLAKE2b256; return true;
                case "BLAKE2B384": case "BLAKE2B-384": algorithmName = BLAKE2b384; return true;
                case "BLAKE2B512": case "BLAKE2B-512": algorithmName = BLAKE2b512; return true;
                case "BLAKE2S256": case "BLAKE2S-256": algorithmName = BLAKE2s256; return true;
                //case "CSHAKE128":case "CSHAKE-128": algorithmName = CSHAKE128; return true;
                //case "CSHAKE256":case "CSHAKE-256": algorithmName = CSHAKE256; return true;
                //case "DSTU7564-256": algorithmName = DSTU7564_256; return true;
                //case "DSTU7564-384": algorithmName = DSTU7564_384; return true;
                //case "DSTU7564-512": algorithmName = DSTU7564_512; return true;
                //case "GOST3411": algorithmName = GOST3411; return true;
                //case "GOST3411-2012-256": algorithmName = GOST3411_2012_256; return true;
                //case "GOST3411-2012-512": algorithmName = GOST3411_2012_512; return true;
                //case "KECCAK128":case "KECCAK-128": algorithmName = Keccak128; return true;
                //case "KECCAK224":case "KECCAK-224": algorithmName = Keccak224; return true;
                //case "KECCAK256":case "KECCAK-256": algorithmName = Keccak256; return true;
                //case "KECCAK288":case "KECCAK-288": algorithmName = Keccak288; return true;
                //case "KECCAK384":case "KECCAK-384": algorithmName = Keccak384; return true;
                //case "KECCAK512":case "KECCAK-512": algorithmName = Keccak512; return true;
                case "MD2": algorithmName = MD2; return true;
                //case "MD4": algorithmName = MD4; return true;
                //case "MD5": algorithmName = MD5; return true;
                //case "RIPEMD128": case "RIPEMD-128": algorithmName = RIPEMD128; return true;
                //case "RIPEMD160": case "RIPEMD-160": algorithmName = RIPEMD160; return true;
                //case "RIPEMD256": case "RIPEMD-256": algorithmName = RIPEMD256; return true;
                //case "RIPEMD320": case "RIPEMD-320": algorithmName = RIPEMD320; return true;
                case "SHA1": case "SHA": case "SHA-1": algorithmName = SHA1; return true;
                case "SHA224": algorithmName = SHA224; return true;
                case "SHA256": algorithmName = SHA256; return true;
                case "SHA384": algorithmName = SHA384; return true;
                case "SHA512": algorithmName = SHA512; return true;
                case "SHA512-224": case "SHA512T224": algorithmName = SHA512_224; return true;
                case "SHA512-256": case "SHA512T256": algorithmName = SHA512_256; return true;
                //case "SHA3-224": algorithmName = SHA3_224; return true;
                //case "SHA3-256": algorithmName = SHA3_256; return true;
                //case "SHA3-384": algorithmName = SHA3_384; return true;
                //case "SHA3-512": algorithmName = SHA3_512; return true;
                //case "SHAKE128":case "SHAKE-128": algorithmName = SHAKE128; return true;
                //case "SHAKE256":case "SHAKE-256": algorithmName = SHAKE_56; return true;
                case "SKEIN256-256": case "SKEIN-256-256": algorithmName = Skein256_256; return true;
                case "SKEIN512-512": case "SKEIN-512-512": algorithmName = Skein512_512; return true;
                case "SKEIN1024-1024": case "SKEIN-1024-1024": algorithmName = Skein1024_1024; return true;
                //case "SM3": algorithmName = SM3; return true;
                //case "TIGER": algorithmName = Tiger; return true;
                //case "WHIRLPOOL": algorithmName = Whirlpool; return true;
                default: break;
            }
            return TryGetAlgorithmNano(mechanism, out algorithmName);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(HashAlgorithmName other)
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

        private static bool TryGetAlgorithmNano(string mechanism, out HashAlgorithmName algorithmName)
        {
            if (mechanism.StartsWith("BLAKE2B"))
            {
                string cut = mechanism.Substring(7, mechanism.Length - 7);
                cut = cut.TrimStart('-');
                if (int.TryParse(cut, out int hashSize))
                {
                    if (BLAKE2b.ValidHashSize(hashSize))
                    {
                        algorithmName = BLAKE2b.GetAlgorithmName(hashSize);
                        return true;
                    }
                }
            }
            else if (mechanism.StartsWith("BLAKE2S"))
            {
                string cut = mechanism.Substring(7, mechanism.Length - 7);
                cut = cut.TrimStart('-');
                if (int.TryParse(cut, out int hashSize))
                {
                    if (BLAKE2s.ValidHashSize(hashSize))
                    {
                        algorithmName = BLAKE2s.GetAlgorithmName(hashSize);
                        return true;
                    }
                }
            }
            else if (mechanism.StartsWith("SHA512T"))
            {
                string cut = mechanism.Substring(7, mechanism.Length - 7);
                if (int.TryParse(cut, out int hashSize))
                {
                    if (SHA512T.ValidHashSize(hashSize))
                    {
                        algorithmName = SHA512T.GetAlgorithmName(hashSize);
                        return true;
                    }
                }
            }
            else if (mechanism.StartsWith("SHA512"))
            {
                string cut = mechanism.Substring(6, mechanism.Length - 6);
                cut = cut.TrimStart('-');
                if (int.TryParse(cut, out int hashSize))
                {
                    if (SHA512T.ValidHashSize(hashSize))
                    {
                        algorithmName = SHA512T.GetAlgorithmName(hashSize);
                        return true;
                    }
                }
            }
            else if (mechanism.StartsWith("SKEIN"))
            {
                string cut = mechanism.Substring(5, mechanism.Length - 5);
                cut = cut.TrimStart('-');
                string[] splits = cut.Split('-');
                if (splits.Length == 2)
                {
                    if (int.TryParse(splits[0], out int hashSize) && int.TryParse(splits[1], out int stateSize))
                    {
                        if (Skein.ValidHashSize(hashSize) && Skein.ValidStateSize(stateSize))
                        {
                            algorithmName = Skein.GetAlgorithmName(hashSize, stateSize);
                            return true;
                        }
                    }
                }
            }
            algorithmName = null;
            return false;
        }
    }
}