using System;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// HMAC name.
    /// </summary>
    public sealed class HMACName : IEquatable<HMACName>
    {
        #region AlgorithmNames

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_BLAKE2b256 { get; } = new HMACName(HashAlgorithmName.BLAKE2b256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static HMACName HMAC_BLAKE2b384 { get; } = new HMACName(HashAlgorithmName.BLAKE2b384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static HMACName HMAC_BLAKE2b512 { get; } = new HMACName(HashAlgorithmName.BLAKE2b512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_BLAKE2s256 { get; } = new HMACName(HashAlgorithmName.BLAKE2s256);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_CSHAKE128_256 { get; } = new HMACName(HashAlgorithmName.CSHAKE128_256);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static HMACName HMAC_CSHAKE256_512 { get; } = new HMACName(HashAlgorithmName.CSHAKE256_512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_DSTU7564_256 { get; } = new HMACName(HashAlgorithmName.DSTU7564_256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static HMACName HMAC_DSTU7564_384 { get; } = new HMACName(HashAlgorithmName.DSTU7564_384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static HMACName HMAC_DSTU7564_512 { get; } = new HMACName(HashAlgorithmName.DSTU7564_512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_GOST3411 { get; } = new HMACName(HashAlgorithmName.GOST3411);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_GOST3411_2012_256 { get; } = new HMACName(HashAlgorithmName.GOST3411_2012_256);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static HMACName HMAC_GOST3411_2012_512 { get; } = new HMACName(HashAlgorithmName.GOST3411_2012_512);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static HMACName HMAC_Keccak128 { get; } = new HMACName(HashAlgorithmName.Keccak128);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static HMACName HMAC_Keccak224 { get; } = new HMACName(HashAlgorithmName.Keccak224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_Keccak256 { get; } = new HMACName(HashAlgorithmName.Keccak256);

        /// <summary>
        /// Hash size 288 bits.
        /// </summary>
        public static HMACName HMAC_Keccak288 { get; } = new HMACName(HashAlgorithmName.Keccak288);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static HMACName HMAC_Keccak384 { get; } = new HMACName(HashAlgorithmName.Keccak384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static HMACName HMAC_Keccak512 { get; } = new HMACName(HashAlgorithmName.Keccak512);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static HMACName HMAC_MD2 { get; } = new HMACName(HashAlgorithmName.MD2);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static HMACName HMAC_MD4 { get; } = new HMACName(HashAlgorithmName.MD4);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static HMACName HMAC_MD5 { get; } = new HMACName(HashAlgorithmName.MD5);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static HMACName HMAC_RIPEMD128 { get; } = new HMACName(HashAlgorithmName.RIPEMD128);

        /// <summary>
        /// Hash size 160 bits.
        /// </summary>
        public static HMACName HMAC_RIPEMD160 { get; } = new HMACName(HashAlgorithmName.RIPEMD160);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_RIPEMD256 { get; } = new HMACName(HashAlgorithmName.RIPEMD256);

        /// <summary>
        /// Hash size 320 bits.
        /// </summary>
        public static HMACName HMAC_RIPEMD320 { get; } = new HMACName(HashAlgorithmName.RIPEMD320);

        /// <summary>
        /// Hash size 160 bits.
        /// </summary>
        public static HMACName HMAC_SHA1 { get; } = new HMACName(HashAlgorithmName.SHA1);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static HMACName HMAC_SHA224 { get; } = new HMACName(HashAlgorithmName.SHA224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_SHA256 { get; } = new HMACName(HashAlgorithmName.SHA256);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static HMACName HMAC_SHA3_224 { get; } = new HMACName(HashAlgorithmName.SHA3_224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_SHA3_256 { get; } = new HMACName(HashAlgorithmName.SHA3_256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static HMACName HMAC_SHA3_384 { get; } = new HMACName(HashAlgorithmName.SHA3_384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static HMACName HMAC_SHA3_512 { get; } = new HMACName(HashAlgorithmName.SHA3_512);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static HMACName HMAC_SHA384 { get; } = new HMACName(HashAlgorithmName.SHA384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static HMACName HMAC_SHA512 { get; } = new HMACName(HashAlgorithmName.SHA512);

        /// <summary>
        /// SHA512/224 algorithm. Hash size 224 bits.
        /// </summary>
        public static HMACName HMAC_SHA512_224 { get; } = new HMACName(HashAlgorithmName.SHA512_224);

        /// <summary>
        /// SHA512/256 algorithm. Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_SHA512_256 { get; } = new HMACName(HashAlgorithmName.SHA512_256);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_SHAKE128_256 { get; } = new HMACName(HashAlgorithmName.SHAKE128_256);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static HMACName HMAC_SHAKE256_512 { get; } = new HMACName(HashAlgorithmName.SHAKE256_512);

        /// <summary>
        /// Skein1024-1024 algorithm. Hash size 1024 bits.
        /// </summary>
        public static HMACName HMAC_Skein1024_1024 { get; } = new HMACName(HashAlgorithmName.Skein1024_1024);

        /// <summary>
        /// Skein256-256 algorithm. Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_Skein256_256 { get; } = new HMACName(HashAlgorithmName.Skein256_256);

        /// <summary>
        /// Skein512-512 algorithm. Hash size 512 bits.
        /// </summary>
        public static HMACName HMAC_Skein512_512 { get; } = new HMACName(HashAlgorithmName.Skein512_512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static HMACName HMAC_SM3 { get; } = new HMACName(HashAlgorithmName.SM3);

        /// <summary>
        /// Hash size 192 bits.
        /// </summary>
        public static HMACName HMAC_Tiger { get; } = new HMACName(HashAlgorithmName.Tiger);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static HMACName HMAC_Whirlpool { get; } = new HMACName(HashAlgorithmName.Whirlpool);

        #endregion AlgorithmNames

        #region Properties

        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly string _name;

        /// <summary>
        /// Gets hash size bits of the algorithm.
        /// </summary>
        public int HashSize => _hashAlgorithm.HashSize;

        /// <summary>
        /// Gets this algorithm's name.
        /// </summary>
        public string Name => _name;

        internal HashAlgorithmName HashAlgorithm => _hashAlgorithm;

        #endregion Properties

        #region Construction

        internal HMACName(HashAlgorithmName hashAlgorithm)
        {
            _name = $"HMAC-{hashAlgorithm.Name}";
            _hashAlgorithm = hashAlgorithm;
        }

        #endregion Construction

        /// <summary>
        /// Gets all algorithm names of the storage.
        /// </summary>
        /// <returns></returns>
        public static HMACName[] GetNames()
        {
            return new HMACName[]
            {
                HMAC_BLAKE2b256,
                HMAC_BLAKE2b384,
                HMAC_BLAKE2b512,
                HMAC_BLAKE2s256,
                HMAC_CSHAKE128_256,
                HMAC_CSHAKE256_512,
                HMAC_DSTU7564_256,
                HMAC_DSTU7564_384,
                HMAC_DSTU7564_512,
                HMAC_GOST3411,
                HMAC_GOST3411_2012_256,
                HMAC_GOST3411_2012_512,
                HMAC_Keccak128,
                HMAC_Keccak224,
                HMAC_Keccak256,
                HMAC_Keccak288,
                HMAC_Keccak384,
                HMAC_Keccak512,
                HMAC_MD2,
                HMAC_MD4,
                HMAC_MD5,
                HMAC_RIPEMD128,
                HMAC_RIPEMD160,
                HMAC_RIPEMD256,
                HMAC_RIPEMD320,
                HMAC_SHA1,
                HMAC_SHA224,
                HMAC_SHA256,
                HMAC_SHA384,
                HMAC_SHA512,
                HMAC_SHA512_224,
                HMAC_SHA512_256,
                HMAC_SHA3_224,
                HMAC_SHA3_256,
                HMAC_SHA3_384,
                HMAC_SHA3_512,
                HMAC_SHAKE128_256,
                HMAC_SHAKE256_512,
                HMAC_Skein256_256,
                HMAC_Skein512_512,
                HMAC_Skein1024_1024,
                HMAC_SM3,
                HMAC_Tiger,
                HMAC_Whirlpool,
            };
        }

        /// <summary>
        /// Try get algorithm name from mechanism.
        /// </summary>
        /// <param name="mechanism">Algorithm mechanism.</param>
        /// <param name="algorithmName">Algorithm name.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithmName(string mechanism, out HMACName algorithmName)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithmName = null;
                return false;
            }
            mechanism = mechanism.Trim().Replace('_', '-').Replace('/', '-').ToUpperInvariant();
            if (mechanism.EndsWith("-HMAC"))
            {
                mechanism = mechanism.Substring(0, mechanism.Length - 5);
            }
            else if (mechanism.StartsWith("HMAC-"))
            {
                mechanism = mechanism.Substring(5, mechanism.Length - 5);
            }
            else if (mechanism.StartsWith("HMAC"))
            {
                mechanism = mechanism.Substring(4, mechanism.Length - 4);
            }
            else
            {
                algorithmName = null;
                return false;
            }
            switch (mechanism)
            {
                case "BLAKE2B256": case "BLAKE2B-256": algorithmName = HMAC_BLAKE2b256; return true;
                case "BLAKE2B384": case "BLAKE2B-384": algorithmName = HMAC_BLAKE2b384; return true;
                case "BLAKE2B512": case "BLAKE2B-512": algorithmName = HMAC_BLAKE2b512; return true;
                case "BLAKE2S256": case "BLAKE2S-256": algorithmName = HMAC_BLAKE2s256; return true;
                case "CSHAKE128-256": case "CSHAKE-128-256": case "CSHAKE128": case "CSHAKE-128": algorithmName = HMAC_CSHAKE128_256; return true;
                case "CSHAKE256-512": case "CSHAKE-256-512": case "CSHAKE256": case "CSHAKE-256": algorithmName = HMAC_CSHAKE256_512; return true;
                case "DSTU7564-256": case "DSTU-7564-256": algorithmName = HMAC_DSTU7564_256; return true;
                case "DSTU7564-384": case "DSTU-7564-384": algorithmName = HMAC_DSTU7564_384; return true;
                case "DSTU7564-512": case "DSTU-7564-512": algorithmName = HMAC_DSTU7564_512; return true;
                case "GOST3411": algorithmName = HMAC_GOST3411; return true;
                case "GOST3411-2012-256": algorithmName = HMAC_GOST3411_2012_256; return true;
                case "GOST3411-2012-512": algorithmName = HMAC_GOST3411_2012_512; return true;
                case "KECCAK128": case "KECCAK-128": algorithmName = HMAC_Keccak128; return true;
                case "KECCAK224": case "KECCAK-224": algorithmName = HMAC_Keccak224; return true;
                case "KECCAK256": case "KECCAK-256": algorithmName = HMAC_Keccak256; return true;
                case "KECCAK288": case "KECCAK-288": algorithmName = HMAC_Keccak288; return true;
                case "KECCAK384": case "KECCAK-384": algorithmName = HMAC_Keccak384; return true;
                case "KECCAK512": case "KECCAK-512": algorithmName = HMAC_Keccak512; return true;
                case "MD2": algorithmName = HMAC_MD2; return true;
                case "MD4": algorithmName = HMAC_MD4; return true;
                case "MD5": algorithmName = HMAC_MD5; return true;
                case "RIPEMD128": case "RIPEMD-128": algorithmName = HMAC_RIPEMD128; return true;
                case "RIPEMD160": case "RIPEMD-160": algorithmName = HMAC_RIPEMD160; return true;
                case "RIPEMD256": case "RIPEMD-256": algorithmName = HMAC_RIPEMD256; return true;
                case "RIPEMD320": case "RIPEMD-320": algorithmName = HMAC_RIPEMD320; return true;
                case "SHA1": case "SHA": case "SHA-1": algorithmName = HMAC_SHA1; return true;
                case "SHA224": case "SHA-224": algorithmName = HMAC_SHA224; return true;
                case "SHA256": case "SHA-256": algorithmName = HMAC_SHA256; return true;
                case "SHA384": case "SHA-384": algorithmName = HMAC_SHA384; return true;
                case "SHA512": case "SHA-512": algorithmName = HMAC_SHA512; return true;
                case "SHA512-224": case "SHA-512-224": case "SHA512T224": case "SHA-512T224": algorithmName = HMAC_SHA512_224; return true;
                case "SHA512-256": case "SHA-512-256": case "SHA512T256": case "SHA-512T256": algorithmName = HMAC_SHA512_256; return true;
                case "SHA3-224": case "SHA-3-224": algorithmName = HMAC_SHA3_224; return true;
                case "SHA3-256": case "SHA-3-256": algorithmName = HMAC_SHA3_256; return true;
                case "SHA3-384": case "SHA-3-384": algorithmName = HMAC_SHA3_384; return true;
                case "SHA3-512": case "SHA-3-512": algorithmName = HMAC_SHA3_512; return true;
                case "SHAKE128-256": case "SHAKE-128-256": case "SHAKE128": case "SHAKE-128": algorithmName = HMAC_SHAKE128_256; return true;
                case "SHAKE256-512": case "SHAKE-256-512": case "SHAKE256": case "SHAKE-256": algorithmName = HMAC_SHAKE256_512; return true;
                case "SKEIN256-256": case "SKEIN-256-256": algorithmName = HMAC_Skein256_256; return true;
                case "SKEIN512-512": case "SKEIN-512-512": algorithmName = HMAC_Skein512_512; return true;
                case "SKEIN1024-1024": case "SKEIN-1024-1024": algorithmName = HMAC_Skein1024_1024; return true;
                case "SM3": algorithmName = HMAC_SM3; return true;
                case "TIGER": algorithmName = HMAC_Tiger; return true;
                case "WHIRLPOOL": algorithmName = HMAC_Whirlpool; return true;
                default: break;
            }
            if (HashAlgorithmName.TryGetAlgorithmNameNano(mechanism, out HashAlgorithmName hashAlgorithm))
            {
                algorithmName = new HMACName(hashAlgorithm);
                return true;
            }
            algorithmName = null;
            return false;
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(HMACName other)
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