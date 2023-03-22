using Honoo.BouncyCastle.NetStyles.X509.Utilities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System.Collections;
using System.Collections.Generic;
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
        private readonly IDictionary<X509ExtensionLabel, X509Extension> _extensions = new SortedDictionary<X509ExtensionLabel, X509Extension>();
        private readonly AsymmetricKeyParameter _publicKey;
        private readonly IDictionary<X509NameLabel, string> _subjectDN = new SortedDictionary<X509NameLabel, string>();

        /// <summary>
        /// Gets X509 extension collection.
        /// </summary>
        public IDictionary<X509ExtensionLabel, X509Extension> Extensions => _extensions;

        /// <summary>
        /// Gets X509 subject distinct name collection.
        /// </summary>
        public IDictionary<X509NameLabel, string> SubjectDN => _subjectDN;

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
                _subjectDN.Add(X509Utilities.GetX509NameLabel((DerObjectIdentifier)oids[i]), (string)values[i]);
            }
            X509Extensions extensions = certificationRequest.GetRequestedExtensions();
            if (extensions != null)
            {
                foreach (DerObjectIdentifier oid in extensions.GetExtensionOids())
                {
                    _extensions.Add(X509Utilities.GetX509ExtensionLabel(oid), extensions.GetExtension(oid));
                }
            }
        }

        #endregion Construction

        /// <summary>
        /// Verify this certification request by public key .
        /// </summary>
        /// <param name="publicKeyInfo">Public key.</param>
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