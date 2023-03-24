using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using System.IO;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// Parse X509 certificate request to other type.
    /// </summary>
    public sealed class X509CertificateRequestParser
    {
        #region Properties

        private readonly Pkcs10CertificationRequest _certificationRequest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestParser class.
        /// </summary>
        /// <param name="certificationRequest">X509 certificate request.</param>
        public X509CertificateRequestParser(Pkcs10CertificationRequest certificationRequest)
        {
            _certificationRequest = certificationRequest;
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestParser class.
        /// </summary>
        /// <param name="pem">Pem string of X509 certificate request.</param>
        public X509CertificateRequestParser(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                _certificationRequest = (Pkcs10CertificationRequest)obj;
            }
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestParser class.
        /// </summary>
        /// <param name="derEncoded">A byte array of X509 certificate request of DER encoding.</param>
        public X509CertificateRequestParser(byte[] derEncoded)
        {
            _certificationRequest = new Pkcs10CertificationRequest(derEncoded);
        }

        #endregion Construction

        /// <summary>
        /// Parse to <see cref="Pkcs10CertificationRequest"/>.
        /// </summary>
        /// <returns></returns>
        public Pkcs10CertificationRequest ToCertificationRequest()
        {
            return _certificationRequest;
        }

        /// <summary>
        /// Parse to a byte array of DER encoding.
        /// </summary>
        /// <returns></returns>
        public byte[] ToDer()
        {
            return _certificationRequest.GetEncoded();
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
                pemWriter.WriteObject(_certificationRequest);
                return writer.ToString();
            }
        }
    }
}