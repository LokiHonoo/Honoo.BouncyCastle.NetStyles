using Org.BouncyCastle.Crypto;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of asymmetric algorithms must inherit.
    /// </summary>
    public abstract class AsymmetricAlgorithm
    {
        #region Properties

        private readonly AsymmetricAlgorithmKind _kind;
        private readonly string _name;

        /// <summary>
        /// Gets the asymmetric algorithm kind of the algorithm.
        /// </summary>
        public AsymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets the asymmetric algorithm name of the algorithm.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the AsymmetricAlgorithm class.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="kind"></param>
        protected AsymmetricAlgorithm(string name, AsymmetricAlgorithmKind kind)
        {
            _name = name;
            _kind = kind;
        }

        #endregion Construction
        /// <summary>
        /// Reset calculator of the algorithm.
        /// </summary>
        public abstract void Reset();
        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Asymmetric algorithm name.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm Create(AsymmetricAlgorithmName algorithmName)
        {
            return algorithmName.GetAlgorithm();
        }


    }
}