using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System.IO;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// Parse X509 certificate to other type.
    /// </summary>
    public sealed class X509CertificateParser
    {
        #region Properties

        private readonly X509Certificate _certificate;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the X509CertificateParser class.
        /// </summary>
        /// <param name="certificate">X509 certificate.</param>
        public X509CertificateParser(X509Certificate certificate)
        {
            _certificate = certificate;
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateParser class.
        /// </summary>
        /// <param name="pem">Pem string of X509 certificate.</param>
        public X509CertificateParser(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                _certificate = (X509Certificate)obj;
            }
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateParser class.
        /// </summary>
        /// <param name="derEncoded">A byte array of X509 certificate of DER encoding.</param>
        public X509CertificateParser(byte[] derEncoded)
        {
            _certificate = new X509Certificate(derEncoded);
        }

        #endregion Construction

        /// <summary>
        /// Parse to <see cref="X509Certificate"/>.
        /// </summary>
        /// <returns></returns>
        public X509Certificate ToCertificate()
        {
            return _certificate;
        }

        /// <summary>
        /// Parse to a byte array of DER encoding.
        /// </summary>
        /// <returns></returns>
        public byte[] ToDer()
        {
            return _certificate.GetEncoded();
        }

        /// <summary>
        /// Parse to pem string.
        /// </summary>
        /// <returns></returns>
        public string ToPem()
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(_certificate);
                return writer.ToString();
            }
        }
    }
}