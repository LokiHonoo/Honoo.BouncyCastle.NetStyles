using System;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// MAC name.
    /// </summary>
    public sealed class CMACName : IEquatable<CMACName>
    {
        #region Algorithm Names

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static CMACName AES_CMAC { get; } = new CMACName(SymmetricAlgorithmName.AES);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static CMACName Blowfish_CMAC { get; } = new CMACName(SymmetricAlgorithmName.Blowfish);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static CMACName Camellia_CMAC { get; } = new CMACName(SymmetricAlgorithmName.Camellia);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 64 bits. Legal key size 40-128 bits (8 bits increments).
        /// </summary>
        public static CMACName CAST5_CMAC { get; } = new CMACName(SymmetricAlgorithmName.CAST5);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 128-256 bits (8 bits increments).
        /// </summary>
        public static CMACName CAST6_CMAC { get; } = new CMACName(SymmetricAlgorithmName.CAST6);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 64 bits. Legal key size 64 bits.
        /// </summary>
        public static CMACName DES_CMAC { get; } = new CMACName(SymmetricAlgorithmName.DES);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 64 bits. Legal key size 128, 192 bits.
        /// </summary>
        public static CMACName DESede_CMAC { get; } = new CMACName(SymmetricAlgorithmName.DESede);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 128, 256 bits.
        /// </summary>
        public static CMACName DSTU7624_128_CMAC { get; } = new CMACName(SymmetricAlgorithmName.DSTU7624_128);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 64 bits. Legal key size 256 bits.
        /// </summary>
        public static CMACName GOST28147_CMAC { get; } = new CMACName(SymmetricAlgorithmName.GOST28147);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 64 bits. Legal key size 8-128 bits (8 bits increments).
        /// </summary>
        public static CMACName IDEA_CMAC { get; } = new CMACName(SymmetricAlgorithmName.IDEA);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static CMACName Noekeon_CMAC { get; } = new CMACName(SymmetricAlgorithmName.Noekeon);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 64 bits. Legal key size 8-1024 bits (8 bits increments).
        /// </summary>
        public static CMACName RC2_CMAC { get; } = new CMACName(SymmetricAlgorithmName.RC2);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static CMACName RC5_64_CMAC { get; } = new CMACName(SymmetricAlgorithmName.RC5_64);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 64 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static CMACName RC5_CMAC { get; } = new CMACName(SymmetricAlgorithmName.RC5);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public static CMACName RC6_CMAC { get; } = new CMACName(SymmetricAlgorithmName.RC6);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static CMACName Rijndael128_CMAC { get; } = new CMACName(SymmetricAlgorithmName.Rijndael128);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static CMACName SEED_CMAC { get; } = new CMACName(SymmetricAlgorithmName.SEED);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static CMACName Serpent_CMAC { get; } = new CMACName(SymmetricAlgorithmName.Serpent);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static CMACName SKIPJACK_CMAC { get; } = new CMACName(SymmetricAlgorithmName.SKIPJACK);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static CMACName SM4_CMAC { get; } = new CMACName(SymmetricAlgorithmName.SM4);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static CMACName TEA_CMAC { get; } = new CMACName(SymmetricAlgorithmName.TEA);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static CMACName Tnepres_CMAC { get; } = new CMACName(SymmetricAlgorithmName.Tnepres);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static CMACName Twofish_CMAC { get; } = new CMACName(SymmetricAlgorithmName.Twofish);

        /// <summary>
        /// CMAC with symmetric block algorithm. Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static CMACName XTEA_CMAC { get; } = new CMACName(SymmetricAlgorithmName.XTEA);

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

        internal CMACName(SymmetricAlgorithmName symmetricAlgorithm)
        {
            _name = $"{symmetricAlgorithm.Name}/CMAC";
            _symmetricAlgorithm = symmetricAlgorithm;
        }

        #endregion Construction

        /// <summary>
        /// Gets all algorithm names of the storage.
        /// </summary>
        /// <returns></returns>
        public static CMACName[] GetNames()
        {
            return new CMACName[]
            {
                AES_CMAC,
                Blowfish_CMAC,
                Camellia_CMAC,
                CAST5_CMAC,
                CAST6_CMAC,
                DES_CMAC,
                DESede_CMAC,
                DSTU7624_128_CMAC,
                GOST28147_CMAC,
                IDEA_CMAC,
                Noekeon_CMAC,
                RC2_CMAC,
                RC5_CMAC,
                RC5_64_CMAC,
                RC6_CMAC,
                Rijndael128_CMAC,
                SEED_CMAC,
                Serpent_CMAC,
                SKIPJACK_CMAC,
                SM4_CMAC,
                TEA_CMAC,
                Tnepres_CMAC,
                Twofish_CMAC,
                XTEA_CMAC,
            };
        }

        /// <summary>
        /// Try get algorithm name from mechanism.
        /// </summary>
        /// <param name="mechanism">Algorithm mechanism.</param>
        /// <param name="algorithmName">Algorithm name.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithmName(string mechanism, out CMACName algorithmName)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithmName = null;
                return false;
            }
            mechanism = mechanism.Trim().Replace('_', '-').Replace('/', '-').ToUpperInvariant();
            if (mechanism.EndsWith("-CMAC"))
            {
                mechanism = mechanism.Substring(0, mechanism.Length - 5);
            }
            else if (mechanism.StartsWith("CMAC-"))
            {
                mechanism = mechanism.Substring(5, mechanism.Length - 5);
            }
            else if (mechanism.StartsWith("CMAC"))
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
                case "AES": algorithmName = AES_CMAC; return true;
                case "BLOWFISH": algorithmName = Blowfish_CMAC; return true;
                case "CAMELLIA": algorithmName = Camellia_CMAC; return true;
                case "CAST5": algorithmName = CAST5_CMAC; return true;
                case "CAST6": algorithmName = CAST6_CMAC; return true;
                case "DES": algorithmName = DES_CMAC; return true;
                case "DESEDE": case "DESEDE3": case "TDEA": case "TRIPLEDES": case "3DES": algorithmName = DESede_CMAC; return true;
                case "DSTU7624-128": algorithmName = DSTU7624_128_CMAC; return true;
                case "GOST28147": algorithmName = GOST28147_CMAC; return true;
                case "IDEA": algorithmName = IDEA_CMAC; return true;
                case "NOEKEON": algorithmName = Noekeon_CMAC; return true;
                case "RC2": algorithmName = RC2_CMAC; return true;
                case "RC5": case "RC532": algorithmName = RC5_CMAC; return true;
                case "RC5-64": algorithmName = RC5_64_CMAC; return true;
                case "RC6": algorithmName = RC6_CMAC; return true;
                case "RIJNDAEL128": case "RIJNDAEL-128": case "RIJNDAEL": algorithmName = Rijndael128_CMAC; return true;
                case "SEED": algorithmName = SEED_CMAC; return true;
                case "SERPENT": algorithmName = Serpent_CMAC; return true;
                case "SKIPJACK": algorithmName = SKIPJACK_CMAC; return true;
                case "SM4": algorithmName = SM4_CMAC; return true;
                case "TEA": algorithmName = TEA_CMAC; return true;
                case "TNEPRES": algorithmName = Tnepres_CMAC; return true;
                case "TWOFISH": algorithmName = Twofish_CMAC; return true;
                case "XTEA": algorithmName = XTEA_CMAC; return true;
                default: algorithmName = null; return false;
            }
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(CMACName other)
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