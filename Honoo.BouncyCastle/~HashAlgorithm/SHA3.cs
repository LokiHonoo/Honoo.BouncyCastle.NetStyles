using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SHA3 : HashAlgorithm
    {
        #region Properties

        private const string NAME = "SHA3-";
        private static readonly KeySizes[] LEGAL_HASH_SIZES = new KeySizes[] { new KeySizes(224, 224, 0), new KeySizes(256, 512, 128) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SHA3 class.
        /// </summary>
        /// <param name="hashSize">Legal hash size 224, 256, 384, 512 bits.</param>
        public SHA3(int hashSize) : base($"{NAME}{hashSize}", hashSize)
        {
            if (!ValidHashSize(hashSize, out string exception))
            {
                throw new CryptographicException(exception);
            }
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="hashSize">Legal hash size 224, 256, 384, 512 bits.</param>
        /// <returns></returns>
        public static SHA3 Create(int hashSize)
        {
            return new SHA3(hashSize);
        }

        internal static HashAlgorithmName GetAlgorithmName(int hashSize)
        {
            return new HashAlgorithmName($"{NAME}{hashSize}",
                                         hashSize,
                                         () => { return new Sha3Digest(hashSize); },
                                         () => { return new SHA3(hashSize); });
        }

        internal static bool ValidHashSize(int hashSize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_HASH_SIZES, hashSize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal hash size 224, 256, 384, 512 bits.";
                return false;
            }
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new Sha3Digest(_hashSize);
        }
    }
}