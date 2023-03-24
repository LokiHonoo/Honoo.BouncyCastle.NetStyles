using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System.Collections;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// Represents a tiled information over the certification request.
    /// </summary>
    public sealed class X509CertificateRequestTiled
    {
        #region Properties

        private readonly Pkcs10CertificationRequest _csr;
        private readonly X509ExtensionCollection _extensions = new X509ExtensionCollection();
        private readonly AsymmetricKeyParameter _publicKey;
        private readonly X509NameCollection _subjectDN = new X509NameCollection();

        /// <summary>
        /// Gets X509 extension collection.
        /// </summary>
        public X509ExtensionCollection Extensions => _extensions;

        /// <summary>
        /// Gets X509 subject distinct name collection.
        /// </summary>
        public X509NameCollection SubjectDN => _subjectDN;

        internal AsymmetricKeyParameter PublicKey => _publicKey;

        #endregion Properties

        #region Construction

        internal X509CertificateRequestTiled(Pkcs10CertificationRequest certificationRequest)
        {
            _csr = certificationRequest;
            _publicKey = certificationRequest.GetPublicKey();
            CertificationRequestInfo csrInfo = certificationRequest.GetCertificationRequestInfo();
            IList oids = csrInfo.Subject.GetOidList();
            IList values = csrInfo.Subject.GetValueList();
            for (int i = 0; i < oids.Count; i++)
            {
                _subjectDN.Add(new X509NameEntity((DerObjectIdentifier)oids[i], (string)values[i]));
            }
            X509Extensions extensions = certificationRequest.GetRequestedExtensions();
            if (extensions != null)
            {
                foreach (DerObjectIdentifier oid in extensions.GetExtensionOids())
                {
                    X509Extension extension = extensions.GetExtension(oid);
                    _extensions.Add(new X509ExtensionEntity(oid, extension.IsCritical, extension.GetParsedValue()));
                }
            }
        }

        #endregion Construction

        /// <summary>
        /// Verify this certification request by public key .
        /// </summary>
        /// <param name="publicKey">Public key.</param>
        public bool Verify(AsymmetricKeyParameter publicKey)
        {
            if (publicKey.IsPrivate)
            {
                throw new CryptographicException("Verify need a public key.");
            }
            return _csr.Verify(publicKey);
        }

        /// <summary>
        /// Verify this certification request by public key .
        /// </summary>
        /// <param name="publicKeyPem">Public key pem string.</param>
        public bool Verify(string publicKeyPem)
        {
            using (StringReader reader = new StringReader(publicKeyPem))
            {
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(AsymmetricCipherKeyPair))
                {
                    throw new CryptographicException("Verify need a public key.");
                }
                AsymmetricKeyParameter key = (AsymmetricKeyParameter)obj;
                if (key.IsPrivate)
                {
                    throw new CryptographicException("Verify need a public key.");
                }
                return _csr.Verify(key);
            }
        }

        /// <summary>
        /// Verify this certification request by public key .
        /// </summary>
        /// <param name="publicKeyInfo">Public key info.</param>
        public bool Verify(byte[] publicKeyInfo)
        {
            AsymmetricKeyParameter key = PublicKeyFactory.CreateKey(publicKeyInfo);
            if (key.IsPrivate)
            {
                throw new CryptographicException("Verify need a public key.");
            }
            return _csr.Verify(key);
        }
    }
}