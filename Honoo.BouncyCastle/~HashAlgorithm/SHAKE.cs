﻿using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SHAKE : HashAlgorithm
    {
        #region Properties

        private const string NAME = "SHAKE";
        private static readonly KeySizes[] LEGAL_HASH_SIZES = new KeySizes[] { new KeySizes(256, 512, 256) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SHAKE class.
        /// </summary>
        /// <param name="hashSize">Legal hash size 256, 512 bits.</param>
        public SHAKE(int hashSize) : base($"{NAME}{hashSize / 2}-{hashSize}", hashSize)
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
        /// <param name="hashSize">Legal hash size 256, 512 bits.</param>
        /// <returns></returns>
        public static SHAKE Create(int hashSize)
        {
            return new SHAKE(hashSize);
        }

        internal static HashAlgorithmName GetAlgorithmName(int hashSize)
        {
            return new HashAlgorithmName($"{NAME}{hashSize / 2}-{hashSize}",
                                         hashSize,
                                         () => { return new ShakeDigest(hashSize / 2); },
                                         () => { return new SHAKE(hashSize); });
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
                exception = "Legal hash size 256, 512 bits.";
                return false;
            }
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new ShakeDigest(_hashSize / 2);
        }
    }
}