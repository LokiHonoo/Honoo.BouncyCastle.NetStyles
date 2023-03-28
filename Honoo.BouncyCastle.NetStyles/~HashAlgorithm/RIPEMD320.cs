﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class RIPEMD320 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 320;
        private const string NAME = "RIPEMD320";
        private IDigest _digest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the RIPEMD320 class.
        /// </summary>
        public RIPEMD320() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static RIPEMD320 Create()
        {
            return new RIPEMD320();
        }

        /// <inheritdoc/>
        public override int ComputeFinal(byte[] outputBuffer, int offset)
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.DoFinal(outputBuffer, offset);
            return _hashSize / 8;
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
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new RipeMD320Digest(); }, () => { return new RIPEMD320(); });
        }

        private IDigest GetDigest()
        {
            return new RipeMD320Digest();
        }
    }
}