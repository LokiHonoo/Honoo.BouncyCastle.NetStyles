namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Asymmetric encryption algorithm interface.
    /// </summary>
    public interface IAsymmetricEncryptionAlgorithm:IAsymmetricParameters
    {
        /// <summary>
        /// Gets legal input bytes length on decrypt.
        /// </summary>
        int DecryptInputLength { get; }

        /// <summary>
        /// Gets legal input bytes length on decrypt.
        /// </summary>
        int DecryptOutputLength { get; }

        /// <summary>
        /// Gets legal input bytes length on encrypt.
        /// </summary>
        int EncryptInputLength { get; }

        /// <summary>
        /// Gets legal input bytes length on encrypt.
        /// </summary>
        int EncryptOutputLength { get; }

        /// <summary>
        /// Represents the encryption padding mode used in the symmetric algorithm.
        /// </summary>
        AsymmetricEncryptionPaddingMode Padding { get; set; }

        /// <summary>
        /// Decrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="rgb">The encrypted data.</param>
        /// <returns></returns>
        byte[] Decrypt(byte[] rgb);

        /// <summary>
        /// Decrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="buffer">The encrypted data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Decrypt(byte[] buffer, int offset, int length);

        /// <summary>
        /// Auto set <see cref="Padding"/> = <see cref="AsymmetricEncryptionPaddingMode.OAEP"/>, Decrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="buffer">The encrypted data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="hashForOAEP">The hash algorithm name for OAEP padding.</param>
        /// <param name="mgf1ForOAEP">The mgf1 algorithm name for OAEP padding.</param>
        /// <returns></returns>
        byte[] Decrypt(byte[] buffer, int offset, int length, HashAlgorithmName hashForOAEP, HashAlgorithmName mgf1ForOAEP);

        /// <summary>
        /// Encrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="rgb">The data to be decrypted.</param>
        /// <returns></returns>
        byte[] Encrypt(byte[] rgb);


        /// <summary>
        /// Encrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="buffer">The data buffer to be decrypted.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Encrypt(byte[] buffer, int offset, int length);

        /// <summary>
        /// Auto set <see cref="Padding"/> = <see cref="AsymmetricEncryptionPaddingMode.OAEP"/>, Encrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="buffer">The data buffer to be decrypted.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="hashForOAEP">The hash algorithm name for OAEP padding.</param>
        /// <param name="mgf1ForOAEP">The mgf1 algorithm name for OAEP padding.</param>
        /// <returns></returns>
        byte[] Encrypt(byte[] buffer, int offset, int length, HashAlgorithmName hashForOAEP, HashAlgorithmName mgf1ForOAEP);
    }
}