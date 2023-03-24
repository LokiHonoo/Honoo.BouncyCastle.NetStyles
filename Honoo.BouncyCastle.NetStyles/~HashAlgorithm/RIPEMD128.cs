using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class RIPEMD128 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 128;
        private const string NAME = "RIPEMD128";
        private IDigest _digest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the RIPEMD128 class.
        /// </summary>
        public RIPEMD128() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static RIPEMD128 Create()
        {
            return new RIPEMD128();
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
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new RipeMD128Digest(); }, () => { return new RIPEMD128(); });
        }

        private IDigest GetDigest()
        {
            return new RipeMD128Digest();
        }
    }
}