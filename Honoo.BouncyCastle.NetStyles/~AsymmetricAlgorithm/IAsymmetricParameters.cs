namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Operations algorithm parameters.
    /// </summary>
    public interface IAsymmetricParameters : IAsymmetricAlgorithm
    {
        /// <summary>
        /// Exports a bytes array containing the asymmetric algorithm private key information associated.
        /// </summary>
        /// <param name="includePrivate">true to include the private key; otherwise, false.</param>
        /// <returns></returns>
        byte[] ExportKeyInfo(bool includePrivate);

        /// <summary>
        /// Exports a bytes array containing the asymmetric algorithm private key information associated.
        /// </summary>
        /// <param name="pbeAlgorithmName">PBE algorithm name.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        byte[] ExportKeyInfo(PBEAlgorithmName pbeAlgorithmName, string password);

        /// <summary>
        /// Exports a pem string containing the asymmetric algorithm key information associated.
        /// </summary>
        /// <param name="includePrivate">true to include the private key; otherwise, false.</param>
        /// <returns></returns>
        string ExportPem(bool includePrivate);

        /// <summary>
        /// Exports a pem string containing the asymmetric algorithm private key information associated.
        /// </summary>
        /// <param name="dekAlgorithmName">DEK algorithm name.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        string ExportPem(DEKAlgorithmName dekAlgorithmName, string password);

        /// <summary>
        /// Renew private key and public key of the algorithm by default.
        /// </summary>
        void GenerateParameters();

        /// <summary>
        /// Imports a byte array that represents asymmetric algorithm key information.
        /// </summary>
        /// <param name="keyInfo">A byte buffer that represents an asymmetric algorithm key.</param>
        void ImportKeyInfo(byte[] keyInfo);

        /// <summary>
        /// Imports a byte array that represents asymmetric algorithm key information.
        /// </summary>
        /// <param name="keyInfo">A byte buffer that represents an asymmetric algorithm key.</param>
        /// <param name="password"></param>
        void ImportKeyInfo(byte[] keyInfo, string password);

        /// <summary>
        /// Imports a pem string that represents asymmetric algorithm key information.
        /// </summary>
        /// <param name="pem">A pem string that represents an asymmetric algorithm key.</param>
        void ImportPem(string pem);

        /// <summary>
        /// Imports a pem string that represents asymmetric algorithm private key information.
        /// </summary>
        /// <param name="pem">A pem string that represents an asymmetric algorithm private key.</param>
        /// <param name="password"></param>
        void ImportPem(string pem, string password);
    }
}