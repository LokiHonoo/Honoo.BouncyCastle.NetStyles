using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SHA512T : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] LEGAL_HASH_SIZES = new KeySizes[] { new KeySizes(224, 376, 8), new KeySizes(392, 504, 8) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SHA512T class.
        /// </summary>
        /// <param name="hashSize">Legal hash size 224-376 bits (8 bits increments), 392-504 bits (8 bits increments).</param>
        public SHA512T(int hashSize) : base($"SHA512/{hashSize}", hashSize)
        {
            if (!DetectionUtilities.ValidSize(LEGAL_HASH_SIZES, hashSize))
            {
                throw new CryptographicException("Legal hash size 224-376 bits (8 bits increments), 392-504 bits (8 bits increments).");
            }
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="hashSize">Legal hash size 224-376 bits (8 bits increments), 392-504 bits (8 bits increments).</param>
        /// <returns></returns>
        public static SHA512T Create(int hashSize)
        {
            return new SHA512T(hashSize);
        }

        internal static HashAlgorithmName GetAlgorithmName(int hashSize)
        {
            return new HashAlgorithmName($"SHA512/{hashSize}",
                                         hashSize,
                                         () => { return new Sha512tDigest(hashSize); },
                                         () => { return new SHA512T(hashSize); });
        }

        internal static bool ValidHashSize(int hashSize)
        {
            return DetectionUtilities.ValidSize(LEGAL_HASH_SIZES, hashSize);
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new Sha512tDigest(_hashSize);
        }
    }
}