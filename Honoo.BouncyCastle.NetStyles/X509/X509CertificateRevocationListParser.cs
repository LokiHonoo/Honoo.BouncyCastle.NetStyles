using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System.IO;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// Parse X509 certificate revocation list to other type.
    /// </summary>
    public sealed class X509CertificateRevocationListParser
    {
        #region Properties

        private readonly X509Crl _certificateRevocationList;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the X509CertificateRevocationListParser class.
        /// </summary>
        /// <param name="certificateRevocationList">X509 certificate revocation list.</param>
        public X509CertificateRevocationListParser(X509Crl certificateRevocationList)
        {
            _certificateRevocationList = certificateRevocationList;
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRevocationListParser class.
        /// </summary>
        /// <param name="pem">Pem string of X509 certificate revocation list.</param>
        public X509CertificateRevocationListParser(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                _certificateRevocationList = (X509Crl)obj;
            }
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRevocationListParser class.
        /// </summary>
        /// <param name="derEncoded">A byte array of X509 certificate revocation list of DER encoding.</param>
        public X509CertificateRevocationListParser(byte[] derEncoded)
        {
            _certificateRevocationList = new X509Crl(derEncoded);
        }

        #endregion Construction

        /// <summary>
        /// Parse to <see cref="X509Crl"/>.
        /// </summary>
        /// <returns></returns>
        public X509Crl ToCertificateRevocationList()
        {
            return _certificateRevocationList;
        }

        /// <summary>
        /// Parse to a byte array of DER encoding.
        /// </summary>
        /// <returns></returns>
        public byte[] ToDer()
        {
            return _certificateRevocationList.GetEncoded();
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
                pemWriter.WriteObject(_certificateRevocationList);
                return writer.ToString();
            }
        }
    }
}