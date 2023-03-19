using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class BLAKE2s : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] LEGAL_HASH_SIZES = new KeySizes[] { new KeySizes(8, 256, 8) };
        private readonly byte[] _key;
        private readonly byte[] _personalization;
        private readonly byte[] _salt;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the BLAKE2s class.
        /// </summary>
        /// <param name="hashSize">Legal hash size 8-256 bits (8 bits increments).</param>
        /// <param name="key">Key need null or less than 32 bytes.</param>
        /// <param name="salt">Salt need null or less than 8 bytes.</param>
        /// <param name="personalization">Personalization need null or less than 8 bytes.</param>
        public BLAKE2s(int hashSize, byte[] key = null, byte[] salt = null, byte[] personalization = null) : base($"BLAKE2s{hashSize}", hashSize)
        {
            if (!DetectionUtilities.ValidSize(LEGAL_HASH_SIZES, hashSize))
            {
                throw new CryptographicException("Legal hash size 8-256 bits (8 bits increments).");
            }
            if (key != null && key.Length != 32)
            {
                throw new CryptographicException("Argument key length need null or less than 32 bytes.");
            }
            if (salt != null && key.Length != 8)
            {
                throw new CryptographicException("Argument salt length need null or less than 8 bytes.");
            }
            if (personalization != null && key.Length != 8)
            {
                throw new CryptographicException("Argument personalization length need null or less than 8 bytes.");
            }
            _key = key;
            _salt = salt;
            _personalization = personalization;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="hashSize">Legal hash size 8-256 bits (8 bits increments).</param>
        /// <param name="key">Key need null or less than 32 bytes.</param>
        /// <param name="salt">Salt need null or less than 8 bytes.</param>
        /// <param name="personalization">Personalization need null or less than 8 bytes.</param>
        /// <returns></returns>
        public static BLAKE2s Create(int hashSize, byte[] key = null, byte[] salt = null, byte[] personalization = null)
        {
            return new BLAKE2s(hashSize, key, salt, personalization);
        }

        internal static HashAlgorithmName GetAlgorithmName(int hashSize)
        {
            return new HashAlgorithmName($"BLAKE2s{hashSize}",
                                         hashSize,
                                         () => { return new Blake2sDigest(hashSize); },
                                         () => { return new BLAKE2s(hashSize); });
        }

        internal static bool ValidHashSize(int hashSize)
        {
            return DetectionUtilities.ValidSize(LEGAL_HASH_SIZES, hashSize);
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new Blake2sDigest(_key, _hashSize / 8, _salt, _personalization);
        }
    }
}