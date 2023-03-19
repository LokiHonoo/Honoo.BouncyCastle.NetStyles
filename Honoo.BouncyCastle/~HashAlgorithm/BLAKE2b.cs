using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class BLAKE2b : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _legalHashSizes = new KeySizes[] { new KeySizes(8, 512, 8) };
        private readonly byte[] _key;
        private readonly byte[] _personalization;
        private readonly byte[] _salt;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the BLAKE2b class.
        /// </summary>
        /// <param name="hashSize">Legal hash size 8-512 bits (8 bits increments).</param>
        public BLAKE2b(int hashSize) : base($"BLAKE2b{hashSize}", hashSize)
        {
            if (!DetectionUtilities.ValidSize(_legalHashSizes, hashSize))
            {
                throw new CryptographicException("Legal hash size 8-512 bits (8 bits increments).");
            }
        }

        /// <summary>
        /// Initializes a new instance of the BLAKE2b class.
        /// </summary>
        /// <param name="hashSize">Legal hash size 8-512 bits (8 bits increments).</param>
        /// <param name="key">Key need null or less than 64 bytes.</param>
        /// <param name="salt">Salt need null or less than 16 bytes.</param>
        /// <param name="personalization">Personalization need null or less than 16 bytes.</param>
        public BLAKE2b(int hashSize, byte[] key, byte[] salt, byte[] personalization) : base($"BLAKE2b{hashSize}", hashSize)
        {
            if (key != null && key.Length != 64)
            {
                throw new CryptographicException("Argument key length need null or less than 64 bytes.");
            }
            if (salt != null && key.Length != 16)
            {
                throw new CryptographicException("Argument salt length need null or less than 16 bytes.");
            }
            if (personalization != null && key.Length != 16)
            {
                throw new CryptographicException("Argument personalization length need null or less than 16 bytes.");
            }
            _key = key;
            _salt = salt;
            _personalization = personalization;
        }

        #endregion Construction

        internal static HashAlgorithmName GetAlgorithmName(int hashSize)
        {
            if (DetectionUtilities.ValidSize(_legalHashSizes, hashSize))
            {
                return new HashAlgorithmName($"BLAKE2b{hashSize}",
                                             hashSize,
                                             () => { return new Blake2bDigest(hashSize); },
                                             () => { return new BLAKE2b(hashSize); });
            }
            throw new CryptographicException("Legal hash size 8-512 bits (8 bits increments).");
        }

        internal static bool ValidHashSize(int hashSize)
        {
            return DetectionUtilities.ValidSize(_legalHashSizes, hashSize);
        }

        /// <inheritdoc/>
        protected override IDigest GenerateDigest()
        {
            return new Blake2bDigest(_key, _hashSize / 8, _salt, _personalization);
        }
    }
}