using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of symmetric algorithms must inherit.
    /// </summary>
    public abstract class SymmetricAlgorithm
    {
        #region Properties

        private readonly SymmetricAlgorithmKind _kind;
        private readonly string _name;

        /// <summary>
        /// Gets iv size bits.
        /// </summary>
        public abstract int IVSize { get; }

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        public abstract int KeySize { get; }

        /// <summary>
        /// Gets symmetric algorithm kind of the algorithm.
        /// </summary>
        public SymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets legal iv size bits.
        /// </summary>
        public abstract KeySizes[] LegalIVSizes { get; }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public abstract KeySizes[] LegalKeySizes { get; }

        /// <summary>
        /// Gets symmetric algorithm name of the algorithm.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SymmetricAlgorithm class.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="kind"></param>
        protected SymmetricAlgorithm(string name, SymmetricAlgorithmKind kind)
        {
            _name = name;
            _kind = kind;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Asymmetric algorithm name.</param>
        /// <returns></returns>
        public static SymmetricAlgorithm Create(SymmetricAlgorithmName algorithmName)
        {
            return algorithmName.GenerateAlgorithm();
        }

        /// <summary>
        /// Determines whether the specified iv size is valid for the current algorithm.
        /// </summary>
        /// <param name="ivSize">IV size bits.</param>
        /// <returns></returns>
        public abstract bool ValidIVSize(int ivSize);

        /// <summary>
        /// Determines whether the specified key size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <returns></returns>
        public abstract bool ValidKeySize(int keySize);
    }
}