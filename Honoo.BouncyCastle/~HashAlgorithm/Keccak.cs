using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Keccak : HashAlgorithm
    {
        #region Properties

        private const string NAME = "Keccak";

        private static readonly KeySizes[] LEGAL_HASH_SIZES = new KeySizes[]
        {
            new KeySizes(128, 128, 0),
            new KeySizes(224, 224, 0),
            new KeySizes(256, 256, 0),
            new KeySizes(288, 288, 0),
            new KeySizes(384, 384, 0),
            new KeySizes(512, 512, 0)
        };

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Keccak class.
        /// </summary>
        /// <param name="hashSize">Legal hash size 128, 224, 256, 288, 384, 512 bits.</param>
        public Keccak(int hashSize) : base($"{NAME}{hashSize}", hashSize)
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
        /// <param name="hashSize">Legal hash size 128, 224, 256, 288, 384, 512 bits.</param>
        /// <returns></returns>
        public static Keccak Create(int hashSize)
        {
            return new Keccak(hashSize);
        }

        internal static HashAlgorithmName GetAlgorithmName(int hashSize)
        {
            return new HashAlgorithmName($"{NAME}{hashSize}",
                                         hashSize,
                                         () => { return new KeccakDigest(hashSize); },
                                         () => { return new Keccak(hashSize); });
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
                exception = "Legal hash size 128, 224, 256, 288, 384, 512 bits.";
                return false;
            }
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new KeccakDigest(_hashSize);
        }
    }
}