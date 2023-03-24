namespace Honoo.BouncyCastle.NetStyles
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
        public abstract byte[] ComputeFinal();

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="rgb">The data to be hash.</param>
        public byte[] ComputeFinal(byte[] rgb)
        {
            Update(rgb, 0, rgb.Length);
            return ComputeFinal();
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="buffer">The data buffer to be hash.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        public byte[] ComputeFinal(byte[] buffer, int offset, int length)
        {
            Update(buffer, offset, length);
            return ComputeFinal();
        }

        /// <summary>
        /// Get <see cref="System.Security.Cryptography.HashAlgorithm"/> if algorithm has .NET implementation.
        /// </summary>
        /// <returns></returns>
        public System.Security.Cryptography.HashAlgorithm GetNetAlgorithm()
        {
            return System.Security.Cryptography.HashAlgorithm.Create(_name);
        }

        /// <summary>
        /// Reset calculator of the algorithm.
        /// </summary>
        public abstract void Reset();

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
        public abstract void Update(byte[] buffer, int offset, int length);
    }
}