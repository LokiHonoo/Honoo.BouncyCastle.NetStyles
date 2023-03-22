using System;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// MAC name.
    /// </summary>
    public sealed class MACName : IEquatable<MACName>
    {
        #region Algorithm Names

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static MACName AES_MAC { get; } = new MACName(SymmetricAlgorithmName.AES);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static MACName Blowfish_MAC { get; } = new MACName(SymmetricAlgorithmName.Blowfish);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static MACName Camellia_MAC { get; } = new MACName(SymmetricAlgorithmName.Camellia);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 64 bits. Legal key size 40-128 bits (8 bits increments).
        /// </summary>
        public static MACName CAST5_MAC { get; } = new MACName(SymmetricAlgorithmName.CAST5);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 128-256 bits (8 bits increments).
        /// </summary>
        public static MACName CAST6_MAC { get; } = new MACName(SymmetricAlgorithmName.CAST6);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 64 bits. Legal key size 64 bits.
        /// </summary>
        public static MACName DES_MAC { get; } = new MACName(SymmetricAlgorithmName.DES);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 64 bits. Legal key size 128, 192 bits.
        /// </summary>
        public static MACName DESede_MAC { get; } = new MACName(SymmetricAlgorithmName.DESede);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 128, 256 bits.
        /// </summary>
        public static MACName DSTU7624_128_MAC { get; } = new MACName(SymmetricAlgorithmName.DSTU7624_128);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 256 bits. Legal key size 256, 512 bits.
        /// </summary>
        public static MACName DSTU7624_256_MAC { get; } = new MACName(SymmetricAlgorithmName.DSTU7624_256);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 512 bits. Legal key size 512 bits.
        /// </summary>
        public static MACName DSTU7624_512_MAC { get; } = new MACName(SymmetricAlgorithmName.DSTU7624_512);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 64 bits. Legal key size 256 bits.
        /// </summary>
        public static MACName GOST28147_MAC { get; } = new MACName(SymmetricAlgorithmName.GOST28147);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 64 bits. Legal key size 8-128 bits (8 bits increments).
        /// </summary>
        public static MACName IDEA_MAC { get; } = new MACName(SymmetricAlgorithmName.IDEA);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static MACName Noekeon_MAC { get; } = new MACName(SymmetricAlgorithmName.Noekeon);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 64 bits. Legal key size 8-1024 bits (8 bits increments).
        /// </summary>
        public static MACName RC2_MAC { get; } = new MACName(SymmetricAlgorithmName.RC2);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static MACName RC5_64_MAC { get; } = new MACName(SymmetricAlgorithmName.RC5_64);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 64 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static MACName RC5_MAC { get; } = new MACName(SymmetricAlgorithmName.RC5);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public static MACName RC6_MAC { get; } = new MACName(SymmetricAlgorithmName.RC6);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static MACName Rijndael128_MAC { get; } = new MACName(SymmetricAlgorithmName.Rijndael128);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 160 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static MACName Rijndael160_MAC { get; } = new MACName(SymmetricAlgorithmName.Rijndael160);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 192 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static MACName Rijndael192_MAC { get; } = new MACName(SymmetricAlgorithmName.Rijndael192);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 224 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static MACName Rijndael224_MAC { get; } = new MACName(SymmetricAlgorithmName.Rijndael224);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 256 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static MACName Rijndael256_MAC { get; } = new MACName(SymmetricAlgorithmName.Rijndael256);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static MACName SEED_MAC { get; } = new MACName(SymmetricAlgorithmName.SEED);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static MACName Serpent_MAC { get; } = new MACName(SymmetricAlgorithmName.Serpent);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static MACName SKIPJACK_MAC { get; } = new MACName(SymmetricAlgorithmName.SKIPJACK);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static MACName SM4_MAC { get; } = new MACName(SymmetricAlgorithmName.SM4);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static MACName TEA_MAC { get; } = new MACName(SymmetricAlgorithmName.TEA);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 1024 bits. Legal key size 1024 bits.
        /// </summary>
        public static MACName Threefish1024_MAC { get; } = new MACName(SymmetricAlgorithmName.Threefish1024);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 256 bits. Legal key size 256 bits.
        /// </summary>
        public static MACName Threefish256_MAC { get; } = new MACName(SymmetricAlgorithmName.Threefish256);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 512 bits. Legal key size 512 bits.
        /// </summary>
        public static MACName Threefish512_MAC { get; } = new MACName(SymmetricAlgorithmName.Threefish512);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static MACName Tnepres_MAC { get; } = new MACName(SymmetricAlgorithmName.Tnepres);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static MACName Twofish_MAC { get; } = new MACName(SymmetricAlgorithmName.Twofish);

        /// <summary>
        /// MAC with symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static MACName XTEA_MAC { get; } = new MACName(SymmetricAlgorithmName.XTEA);

        #endregion Algorithm Names

        #region Properties

        private readonly string _name;
        private readonly SymmetricAlgorithmName _symmetricAlgorithm;

        /// <summary>
        /// Gets block size bits.
        /// </summary>
        public int BlockSize => _symmetricAlgorithm.BlockSize;

        /// <summary>
        /// Gets this algorithm's name.
        /// </summary>
        public string Name => _name;

        internal SymmetricAlgorithmName SymmetricAlgorithm => _symmetricAlgorithm;

        #endregion Properties

        #region Construction

        internal MACName(SymmetricAlgorithmName symmetricAlgorithm)
        {
            _name = $"{symmetricAlgorithm.Name}/MAC";
            _symmetricAlgorithm = symmetricAlgorithm;
        }

        #endregion Construction

        /// <summary>
        /// Gets all algorithm names of the storage.
        /// </summary>
        /// <returns></returns>
        public static MACName[] GetNames()
        {
            return new MACName[]
            {
                AES_MAC,
                Blowfish_MAC,
                Camellia_MAC,
                CAST5_MAC,
                CAST6_MAC,
                DES_MAC,
                DESede_MAC,
                DSTU7624_128_MAC,
                DSTU7624_256_MAC,
                DSTU7624_512_MAC,
                GOST28147_MAC,
                IDEA_MAC,
                Noekeon_MAC,
                RC2_MAC,
                RC5_MAC,
                RC5_64_MAC,
                RC6_MAC,
                Rijndael128_MAC,
                Rijndael160_MAC,
                Rijndael192_MAC,
                Rijndael224_MAC,
                Rijndael256_MAC,
                SEED_MAC,
                Serpent_MAC,
                SKIPJACK_MAC,
                SM4_MAC,
                TEA_MAC,
                Threefish256_MAC,
                Threefish512_MAC,
                Threefish1024_MAC,
                Tnepres_MAC,
                Twofish_MAC,
                XTEA_MAC,
            };
        }

        /// <summary>
        /// Try get algorithm name from mechanism.
        /// </summary>
        /// <param name="mechanism">Algorithm mechanism.</param>
        /// <param name="algorithmName">Algorithm name.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithmName(string mechanism, out MACName algorithmName)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithmName = null;
                return false;
            }
            mechanism = mechanism.Trim().Replace('_', '-').Replace('/', '-').ToUpperInvariant();
            if (mechanism.EndsWith("-MAC"))
            {
                mechanism = mechanism.Substring(0, mechanism.Length - 4);
            }
            else if (mechanism.StartsWith("MAC-"))
            {
                mechanism = mechanism.Substring(4, mechanism.Length - 4);
            }
            else if (mechanism.StartsWith("MAC"))
            {
                mechanism = mechanism.Substring(3, mechanism.Length - 3);
            }
            else
            {
                algorithmName = null;
                return false;
            }
            switch (mechanism)
            {
                case "AES": algorithmName = AES_MAC; return true;
                case "BLOWFISH": algorithmName = Blowfish_MAC; return true;
                case "CAMELLIA": algorithmName = Camellia_MAC; return true;
                case "CAST5": algorithmName = CAST5_MAC; return true;
                case "CAST6": algorithmName = CAST6_MAC; return true;
                case "DES": algorithmName = DES_MAC; return true;
                case "DESEDE": case "DESEDE3": case "TDEA": case "TRIPLEDES": case "3DES": algorithmName = DESede_MAC; return true;
                case "DSTU7624-128": algorithmName = DSTU7624_128_MAC; return true;
                case "DSTU7624-256": algorithmName = DSTU7624_256_MAC; return true;
                case "DSTU7624-512": algorithmName = DSTU7624_512_MAC; return true;
                case "GOST28147": algorithmName = GOST28147_MAC; return true;
                case "IDEA": algorithmName = IDEA_MAC; return true;
                case "NOEKEON": algorithmName = Noekeon_MAC; return true;
                case "RC2": algorithmName = RC2_MAC; return true;
                case "RC5": case "RC532": algorithmName = RC5_MAC; return true;
                case "RC5-64": algorithmName = RC5_64_MAC; return true;
                case "RC6": algorithmName = RC6_MAC; return true;
                case "RIJNDAEL128": case "RIJNDAEL-128": case "RIJNDAEL": algorithmName = Rijndael128_MAC; return true;
                case "RIJNDAEL160": case "RIJNDAEL-160": algorithmName = Rijndael160_MAC; return true;
                case "RIJNDAEL192": case "RIJNDAEL-192": algorithmName = Rijndael192_MAC; return true;
                case "RIJNDAEL224": case "RIJNDAEL-224": algorithmName = Rijndael224_MAC; return true;
                case "RIJNDAEL256": case "RIJNDAEL-256": algorithmName = Rijndael256_MAC; return true;
                case "SEED": algorithmName = SEED_MAC; return true;
                case "SERPENT": algorithmName = Serpent_MAC; return true;
                case "SKIPJACK": algorithmName = SKIPJACK_MAC; return true;
                case "SM4": algorithmName = SM4_MAC; return true;
                case "TEA": algorithmName = TEA_MAC; return true;
                case "THREEFISH256": case "THREEFISH-256": case "THREEFISH": algorithmName = Threefish256_MAC; return true;
                case "THREEFISH512": case "THREEFISH-512": algorithmName = Threefish512_MAC; return true;
                case "THREEFISH1024": case "THREEFISH-1024": algorithmName = Threefish1024_MAC; return true;
                case "TNEPRES": algorithmName = Tnepres_MAC; return true;
                case "TWOFISH": algorithmName = Twofish_MAC; return true;
                case "XTEA": algorithmName = XTEA_MAC; return true;
                default: algorithmName = null; return false;
            }
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(MACName other)
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