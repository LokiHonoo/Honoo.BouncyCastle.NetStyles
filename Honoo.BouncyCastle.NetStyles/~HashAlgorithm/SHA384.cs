﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SHA384 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 384;
        private const string NAME = "SHA384";
        private IDigest _digest;
        #endregion Properties
        #region Construction

        /// <summary>
        /// Initializes a new instance of the SHA384 class.
        /// </summary>
        public SHA384() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction
        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static SHA384 Create()
        {
            return new SHA384();
        }
        /// <inheritdoc/>
        public override byte[] ComputeFinal()
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            byte[] hash = new byte[_hashSize / 8];
            _digest.DoFinal(hash, 0);
            return hash;
        }
        /// <inheritdoc/>
        public override void Reset()
        {
            _digest.Reset();
        }

        /// <inheritdoc/>
        public override void Update(byte[] buffer, int offset, int length)
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.BlockUpdate(buffer, offset, length);
        }
        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new Sha384Digest(); }, () => { return new SHA384(); });
        }
        private IDigest GetDigest()
        {
            return new Sha384Digest();
        }
    }
}