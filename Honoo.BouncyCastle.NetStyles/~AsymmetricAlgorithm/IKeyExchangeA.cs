namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Key exchange algorithm party A's interface.
    /// </summary>
    public interface IKeyExchangeA : IAsymmetricAlgorithm
    {
        /// <summary>
        /// Sand this value to party B.
        /// </summary>
        byte[] G { get; }

        /// <summary>
        /// Sand this value to party B.
        /// </summary>
        byte[] P { get; }

        /// <summary>
        /// Sand this value to party B.
        /// </summary>
        byte[] PublicKeyA { get; }

        /// <summary>
        /// Derive key material from the party B's exchange.
        /// </summary>
        /// <param name="publicKeyB">The party B's public key blob.</param>
        /// <param name="unsigned">Output unsigned bytes.</param>
        /// <returns></returns>
        byte[] DeriveKeyMaterial(byte[] publicKeyB, bool unsigned);

        /// <summary>
        /// Renew key exchange parameters of the algorithm by default.
        /// </summary>
        void GenerateParameters();

        /// <summary>
        /// Renew key exchange parameters of the algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.</param>
        /// <param name="certainty">Legal certainty is more than 0.</param>
        void GenerateParameters(int keySize = 521, int certainty = 20);
    }
}