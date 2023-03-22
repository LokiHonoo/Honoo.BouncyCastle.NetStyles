using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using System;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// X509 certificate revocation entity.
    /// </summary>
    public sealed class X509RevocationEntity
    {
        #region Properties

        private readonly X509Extensions _extensions;
        private readonly DateTime _revocationDate;
        private readonly BigInteger _serialNumber;

        /// <summary>
        /// Revocation extensions.
        /// </summary>
        public X509Extensions Extensions => _extensions;

        /// <summary>
        /// Revocation date.
        /// </summary>
        public DateTime RevocationDate => _revocationDate;

        /// <summary>
        /// Certificate serial number.
        /// </summary>
        public BigInteger SerialNumber => _serialNumber;

        #endregion Properties

        /// <summary>
        /// X509 certificate revocation entity.
        /// </summary>
        /// <param name="serialNumber">Certificate serial number.</param>
        /// <param name="revocationDate">Revocation date.</param>
        /// <param name="extensions">Revocation extensions.</param>
        public X509RevocationEntity(BigInteger serialNumber, DateTime revocationDate, X509Extensions extensions)
        {
            _serialNumber = serialNumber;
            _revocationDate = revocationDate;
            _extensions = extensions;
        }
    }
}