using Org.BouncyCastle.Crypto;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Asymmetric algorithm interface.
    /// </summary>
    public interface IAsymmetricAlgorithm
    {
        /// <summary>
        /// Gets the asymmetric algorithm kind of the algorithm.
        /// </summary>
        AsymmetricAlgorithmKind Kind { get; }

        /// <summary>
        /// Gets the asymmetric algorithm name of the algorithm.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Exports a bytes array containing the asymmetric algorithm private key information associated.
        /// </summary>
        /// <param name="includePrivate">Indicates whether the private key is included.</param>
        /// <returns></returns>
        byte[] ExportKeyInfo(bool includePrivate);

        /// <summary>
        /// Exports a bytes array containing the asymmetric algorithm private key information associated.
        /// </summary>
        /// <param name="pbeAlgorithmName">PBE algorithm name.</param>
        /// <param name="password">Using encrypt private key.</param>
        /// <returns></returns>
        byte[] ExportKeyInfo(PBEAlgorithmName pbeAlgorithmName, string password);

        /// <summary>
        /// Exports a <see cref="AsymmetricCipherKeyPair"/> containing the asymmetric algorithm key pair information associated.
        /// </summary>
        /// <returns></returns>
        AsymmetricCipherKeyPair ExportParameters();

        /// <summary>
        /// Exports a <see cref="AsymmetricKeyParameter"/> containing the asymmetric algorithm key information associated.
        /// </summary>
        /// <param name="privateKey">Indicates whether the private key is exported.</param>
        /// <returns></returns>
        AsymmetricKeyParameter ExportParameters(bool privateKey);

        /// <summary>
        /// Exports a pem string containing the asymmetric algorithm key information associated.
        /// </summary>
        /// <param name="includePrivate">Indicates whether the private key is included.</param>
        /// <returns></returns>
        string ExportPem(bool includePrivate);

        /// <summary>
        /// Exports a pem string containing the asymmetric algorithm private key information associated.
        /// </summary>
        /// <param name="dekAlgorithmName">DEK algorithm name.</param>
        /// <param name="password">Using encrypt private key.</param>
        /// <returns></returns>
        string ExportPem(DEKAlgorithmName dekAlgorithmName, string password);

        /// <summary>
        /// Renew private key and public key of the algorithm by default.
        /// </summary>
        void GenerateParameters();

        /// <summary>
        /// Imports a byte array that represents asymmetric algorithm key information.
        /// <para/>Create public key automatically if imports key is a private key. Remove private key if imports key is a public key.
        /// </summary>
        /// <param name="keyInfo">A byte buffer that represents an asymmetric algorithm key.</param>
        void ImportKeyInfo(byte[] keyInfo);

        /// <summary>
        /// Imports a byte array that represents encrypted asymmetric algorithm key information. The public key is created automatically.
        /// </summary>
        /// <param name="privateKeyInfo">A byte buffer that represents an encrypted asymmetric algorithm private key.</param>
        /// <param name="password">Using decrypt private key.</param>
        void ImportKeyInfo(byte[] privateKeyInfo, string password);

        /// <summary>
        /// Imports a <see cref="AsymmetricCipherKeyPair"/> that represents asymmetric algorithm key pair information.
        /// </summary>
        /// <param name="keyPair">A <see cref="AsymmetricCipherKeyPair"/> that represents an asymmetric algorithm key pair.</param>
        void ImportParameters(AsymmetricCipherKeyPair keyPair);

        /// <summary>
        /// Imports a <see cref="AsymmetricKeyParameter"/> that represents asymmetric algorithm key information.
        /// <para/>Create public key automatically if imports key is a private key. Remove private key if imports key is a public key.
        /// </summary>
        /// <param name="asymmetricKey">A <see cref="AsymmetricKeyParameter"/> that represents an asymmetric algorithm key.</param>
        void ImportParameters(AsymmetricKeyParameter asymmetricKey);

        /// <summary>
        /// Imports a pem string that represents asymmetric algorithm key information.
        /// <para/>Create public key automatically if imports key is a private key. Remove private key if imports key is a public key.
        /// </summary>
        /// <param name="keyPem">A pem string that represents an asymmetric algorithm key.</param>
        void ImportPem(string keyPem);

        /// <summary>
        /// Imports a pem string that represents encrypted asymmetric algorithm private key information, The public key is created automatically.
        /// </summary>
        /// <param name="privateKeyPem">A pem string that represents an encrypted asymmetric algorithm private key.</param>
        /// <param name="password">Using decrypt private key.</param>
        void ImportPem(string privateKeyPem, string password);
    }
}