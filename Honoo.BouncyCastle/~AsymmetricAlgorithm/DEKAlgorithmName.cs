using System;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// DEK algorithm name.
    /// </summary>
    public sealed class DEKAlgorithmName : IEquatable<DEKAlgorithmName>
    {
        #region AlgorithmNames

        /// <summary></summary>
        public static DEKAlgorithmName AES_128_CBC { get; } = new DEKAlgorithmName("AES-128-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName AES_128_CFB { get; } = new DEKAlgorithmName("AES-128-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_128_ECB { get; } = new DEKAlgorithmName("AES-128-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_128_OFB { get; } = new DEKAlgorithmName("AES-128-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_192_CBC { get; } = new DEKAlgorithmName("AES-192-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName AES_192_CFB { get; } = new DEKAlgorithmName("AES-192-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_192_ECB { get; } = new DEKAlgorithmName("AES-192-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_192_OFB { get; } = new DEKAlgorithmName("AES-192-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_256_CBC { get; } = new DEKAlgorithmName("AES-256-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName AES_256_CFB { get; } = new DEKAlgorithmName("AES-256-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_256_ECB { get; } = new DEKAlgorithmName("AES-256-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_256_OFB { get; } = new DEKAlgorithmName("AES-256-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName BLOWFISH_CBC { get; } = new DEKAlgorithmName("BF-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName BLOWFISH_CFB { get; } = new DEKAlgorithmName("BF-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName BLOWFISH_ECB { get; } = new DEKAlgorithmName("BF-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName BLOWFISH_OFB { get; } = new DEKAlgorithmName("BF-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_CBC { get; } = new DEKAlgorithmName("DES-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName DES_CFB { get; } = new DEKAlgorithmName("DES-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_ECB { get; } = new DEKAlgorithmName("DES-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE_CBC { get; } = new DEKAlgorithmName("DES-EDE-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE_CFB { get; } = new DEKAlgorithmName("DES-EDE-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE_ECB { get; } = new DEKAlgorithmName("DES-EDE-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE_OFB { get; } = new DEKAlgorithmName("DES-EDE-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE3_CBC { get; } = new DEKAlgorithmName("DES-EDE3-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE3_CFB { get; } = new DEKAlgorithmName("DES-EDE3-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE3_ECB { get; } = new DEKAlgorithmName("DES-EDE3-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE3_OFB { get; } = new DEKAlgorithmName("DES-EDE3-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_OFB { get; } = new DEKAlgorithmName("DES-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_40_CBC { get; } = new DEKAlgorithmName("RC2-40-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_40_CFB { get; } = new DEKAlgorithmName("RC2-40-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_40_ECB { get; } = new DEKAlgorithmName("RC2-40-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_40_OFB { get; } = new DEKAlgorithmName("RC2-40-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_64_CBC { get; } = new DEKAlgorithmName("RC2-64-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_64_CFB { get; } = new DEKAlgorithmName("RC2-64-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_64_ECB { get; } = new DEKAlgorithmName("RC2-64-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_64_OFB { get; } = new DEKAlgorithmName("RC2-64-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_CBC { get; } = new DEKAlgorithmName("RC2-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_CFB { get; } = new DEKAlgorithmName("RC2-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_ECB { get; } = new DEKAlgorithmName("RC2-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_OFB { get; } = new DEKAlgorithmName("RC2-OFB");

        #endregion AlgorithmNames

        #region Properties

        private readonly string _name;

        /// <summary>
        /// Gets this DEK algorithm's name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Construction

        internal DEKAlgorithmName(string name)
        {
            _name = name;
        }

        #endregion Construction

        /// <summary>
        /// Gets all DEK algorithm names of the storage.
        /// </summary>
        /// <returns></returns>
        public static DEKAlgorithmName[] GetNames()
        {
            return new DEKAlgorithmName[]
            {
                AES_128_CBC,
                AES_128_CFB,
                AES_128_ECB,
                AES_128_OFB,
                AES_192_CBC,
                AES_192_CFB,
                AES_192_ECB,
                AES_192_OFB,
                AES_256_CBC,
                AES_256_CFB,
                AES_256_ECB,
                AES_256_OFB,
                BLOWFISH_CBC,
                BLOWFISH_CFB,
                BLOWFISH_ECB,
                BLOWFISH_OFB,
                DES_CBC,
                DES_CFB,
                DES_ECB,
                DES_EDE_CBC,
                DES_EDE_CFB,
                DES_EDE_ECB,
                DES_EDE_OFB,
                DES_EDE3_CBC,
                DES_EDE3_CFB,
                DES_EDE3_ECB,
                DES_EDE3_OFB,
                DES_OFB,
                RC2_40_CBC,
                RC2_40_CFB,
                RC2_40_ECB,
                RC2_40_OFB,
                RC2_64_CBC,
                RC2_64_CFB,
                RC2_64_ECB,
                RC2_64_OFB,
                RC2_CBC,
                RC2_CFB,
                RC2_ECB,
                RC2_OFB,
            };
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(DEKAlgorithmName other)
        {
            return _name == other._name;
        }

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }
    }
}