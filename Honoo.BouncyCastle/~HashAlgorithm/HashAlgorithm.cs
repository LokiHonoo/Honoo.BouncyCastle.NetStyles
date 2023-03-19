using Org.BouncyCastle.Crypto;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of hash algorithms must inherit.
    /// </summary>
    public abstract class HashAlgorithm
    {
        #region Properties

        /// <summary>
        /// Hash size bits.
        /// </summary>
        protected readonly int _hashSize;

        private readonly string _name;
        private IDigest _digest;

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize => _hashSize;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the HashAlgorithm class.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="hashSize"></param>
        protected HashAlgorithm(string name, int hashSize)
        {
            _name = name;
            _hashSize = hashSize;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Hash algorithm name.</param>
        /// <returns></returns>
        public static HashAlgorithm Create(HashAlgorithmName algorithmName)
        {
            return algorithmName.GetAlgorithm();
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <returns></returns>
        public byte[] ComputeHash()
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            byte[] hash = new byte[_hashSize / 8];
            _digest.DoFinal(hash, 0);
            return hash;
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="rgb">The data to be hash.</param>
        /// <returns></returns>
        public byte[] ComputeHash(byte[] rgb)
        {
            return ComputeHash(rgb, 0, rgb.Length);
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="buffer">The data buffer to be hash.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] ComputeHash(byte[] buffer, int offset, int length)
        {
            Update(buffer, offset, length);
            return ComputeHash();
        }

        /// <summary>
        /// Create HMAC by this hash algorithm.
        /// </summary>
        /// <returns></returns>
        public HMAC CreateHMAC()
        {
            return new HMAC(this);
        }

        /// <summary>
        /// Reset calculator of the algorithm.
        /// </summary>
        public void Reset()
        {
            _digest.Reset();
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="rgb">The data to be hash.</param>
        public void Update(byte[] rgb)
        {
            Update(rgb, 0, rgb.Length);
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="buffer">The data buffer to be hash.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        public void Update(byte[] buffer, int offset, int length)
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.BlockUpdate(buffer, offset, length);
        }

        /// <inheritdoc/>
        protected abstract IDigest GetDigest();
    }
}