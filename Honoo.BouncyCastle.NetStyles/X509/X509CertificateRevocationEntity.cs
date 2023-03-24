using System;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// X509 certificate revocation entity.
    /// </summary>
    public sealed class X509CertificateRevocationEntity
    {
        #region Properties

        private readonly X509ExtensionCollection _extensions;
        private readonly DateTime _revocationDate;
        private readonly string _serialNumber;
        private readonly int _serialNumberDigitBase;

        /// <summary>
        /// Gets certificate revocation extension collection.
        /// </summary>
        public X509ExtensionCollection Extensions => _extensions;

        /// <summary>
        /// Gets certificate revocation date.
        /// </summary>
        public DateTime RevocationDate => _revocationDate;

        /// <summary>
        /// Gets certificate serial number string.
        /// </summary>
        public string SerialNumber => _serialNumber;

        /// <summary>
        /// Gets the digit base of the serial number string.
        /// </summary>
        public int SerialNumberDigitBase => _serialNumberDigitBase;

        #endregion Properties

        /// <summary>
        /// Initializes a new instance of the X509RevocationEntity class.
        /// </summary>
        /// <param name="serialNumber">Certificate serial number string.</param>
        /// <param name="serialNumberDigitBase">Specifies the digit base of the serial number string. e.g. 2, 10, 16.</param>
        /// <param name="revocationDate">Certificate revocation date.</param>
        /// <param name="extensions">Certificate revocation extension collection.</param>
        public X509CertificateRevocationEntity(string serialNumber, int serialNumberDigitBase, DateTime revocationDate, X509ExtensionCollection extensions)
        {
            _serialNumber = serialNumber;
            _serialNumberDigitBase = serialNumberDigitBase;
            _revocationDate = revocationDate;
            _extensions = extensions ?? new X509ExtensionCollection();
        }
    }
}