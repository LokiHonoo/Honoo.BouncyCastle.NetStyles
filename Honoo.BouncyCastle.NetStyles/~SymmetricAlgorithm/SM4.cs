﻿using Honoo.BouncyCastle.NetStyles.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SM4 : SymmetricBlockAlgorithm
    {
        #region Properties

        private const int BLOCK_SIZE = 128;
        private const int DEFAULT_KEY_SIZE = 128;
        private const SymmetricAlgorithmKind KIND = SymmetricAlgorithmKind.Block;
        private const string NAME = "SM4";
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(128, 128, 0) };

        /// <summary>
        /// Gets legal key size bits. Legal key size 128 bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SM4 class.
        /// </summary>
        public SM4() : base(NAME, BLOCK_SIZE, DEFAULT_KEY_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static SM4 Create()
        {
            return new SM4();
        }

        /// <inheritdoc/>
        public override bool ValidKeySize(int keySize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_KEY_SIZES, keySize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal key size 128 bits.";
                return false;
            }
        }

        internal static SymmetricAlgorithmName GetAlgorithmName()
        {
            return new SymmetricAlgorithmName(NAME, KIND, BLOCK_SIZE, () => { return new SM4(); });
        }

        /// <inheritdoc/>
        internal override IBlockCipher GetEngine()
        {
            return new SM4Engine();
        }
    }
}