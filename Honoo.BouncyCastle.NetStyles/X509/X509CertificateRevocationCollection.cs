using System;
using System.Collections;
using System.Collections.Generic;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// X509 certificate revocation collection.
    /// </summary>
    public class X509CertificateRevocationCollection : IEnumerable<X509CertificateRevocationEntity>
    {
        #region Properties

        private readonly IList<X509CertificateRevocationEntity> _elements = new List<X509CertificateRevocationEntity>();
        private readonly ISet<string> _orders = new HashSet<string>();

        /// <summary>
        /// Gets the number of elements contained in the <see cref="X509CertificateRevocationCollection"/>.
        /// </summary>
        public int Count => _orders.Count;

        /// <summary>
        /// Gets the element at the specified serial number string.
        /// </summary>
        /// <param name="serialNumber">The serial number string of the element to get.</param>
        /// <returns></returns>
        public X509CertificateRevocationEntity this[string serialNumber] { get => Get(serialNumber); }

        #endregion Properties

        #region Construction

        internal X509CertificateRevocationCollection()
        {
        }

        #endregion Construction

        /// <summary>
        /// Adds an item to the <see cref="X509CertificateRevocationCollection"/>.
        /// </summary>
        /// <param name="item">The <see cref="X509CertificateRevocationEntity"/> to add to the <see cref="X509CertificateRevocationCollection"/>.</param>
        public void Add(X509CertificateRevocationEntity item)
        {
            _orders.Add(item.SerialNumber);
            _elements.Add(item);
        }

        /// <summary>
        /// Adds an item to the <see cref="X509CertificateRevocationCollection"/>.
        /// </summary>
        /// <param name="serialNumber">Certificate serial number string.</param>
        /// <param name="serialNumberDigitBase">Specifies the digit base of the serial number string. e.g. 2, 10, 16.</param>
        /// <param name="revocationDate">Certificate revocation date.</param>
        /// <param name="extensions">Certificate revocation extension collection.</param>
        public void Add(string serialNumber, int serialNumberDigitBase, DateTime revocationDate, X509ExtensionCollection extensions)
        {
            _orders.Add(serialNumber);
            _elements.Add(new X509CertificateRevocationEntity(serialNumber, serialNumberDigitBase, revocationDate, extensions));
        }

        /// <summary>
        /// Removes all items from the <see cref="X509CertificateRevocationCollection"/>.
        /// </summary>
        public void Clear()
        {
            _orders.Clear();
            _elements.Clear();
        }

        /// <summary>
        /// Determines whether the <see cref="X509CertificateRevocationCollection"/> contains a specific <see cref="string"/>.
        /// </summary>
        /// <param name="serialNumber">A serial number string.</param>
        /// <returns></returns>
        public bool Contains(string serialNumber)
        {
            return _orders.Contains(serialNumber);
        }

        /// <summary>
        /// Copies the elements of the <see cref="X509CertificateRevocationCollection"/> to an System.Array, starting at a particular System.Array index.
        /// </summary>
        /// <param name="array">The one-dimensional System.Array that is the destination of the elements copied from <see cref="X509CertificateRevocationCollection"/>. The System.Array must have zero-based indexing.</param>
        /// <param name="arrayIndex">The zero-based index in array at which copying begins.</param>
        public void CopyTo(X509CertificateRevocationEntity[] array, int arrayIndex)
        {
            _elements.CopyTo(array, arrayIndex);
        }

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns></returns>
        public IEnumerator<X509CertificateRevocationEntity> GetEnumerator()
        {
            return _elements.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Removes the occurrence of a specific serial number string from the <see cref="X509CertificateRevocationCollection"/>.
        /// </summary>
        /// <param name="serialNumber">A serial number string.</param>
        /// <returns>Return true if item was successfully removed, otherwise, false. This method also returns false if item is not found.</returns>
        public bool Remove(string serialNumber)
        {
            if (_orders.Contains(serialNumber))
            {
                _orders.Remove(serialNumber);
                for (int i = _elements.Count - 1; i >= 0; i--)
                {
                    if (_elements[i].SerialNumber == serialNumber)
                    {
                        _elements.RemoveAt(i);
                        return true;
                    }
                }
            }
            return false;
        }

        private X509CertificateRevocationEntity Get(string serialNumber)
        {
            if (_orders.Contains(serialNumber))
            {
                for (int i = _elements.Count - 1; i >= 0; i--)
                {
                    if (_elements[i].SerialNumber == serialNumber)
                    {
                        return _elements[i];
                    }
                }
            }
            return null;
        }
    }
}