using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using System;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// PBE algorithm name.
    /// </summary>
    public sealed class PBEAlgorithmName : IEquatable<PBEAlgorithmName>
    {
        #region Static properties

        /// <summary></summary>
        public static PBEAlgorithmName PBEwithSHAand128BitRC2CBC { get; } = new PBEAlgorithmName("PBEwithSHAand128BitRC2CBC", PkcsObjectIdentifiers.PbeWithShaAnd128BitRC2Cbc);

        /// <summary></summary>
        public static PBEAlgorithmName PBEwithSHAand128BitRC4 { get; } = new PBEAlgorithmName("PBEwithSHAand128BitRC4", PkcsObjectIdentifiers.PbeWithShaAnd128BitRC4);

        /// <summary></summary>
        public static PBEAlgorithmName PBEwithSHAand2KeyDESedeCBC { get; } = new PBEAlgorithmName("PBEwithSHAand2KeyDESedeCBC", PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc);

        /// <summary></summary>
        public static PBEAlgorithmName PBEwithSHAand3KeyDESedeCBC { get; } = new PBEAlgorithmName("PBEwithSHAand3KeyDESedeCBC", PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc);

        /// <summary></summary>
        public static PBEAlgorithmName PBEwithSHAand40BitRC2CBC { get; } = new PBEAlgorithmName("PBEwithSHAand40BitRC2CBC", PkcsObjectIdentifiers.PbewithShaAnd40BitRC2Cbc);

        /// <summary></summary>
        public static PBEAlgorithmName PBEwithSHAand40BitRC4 { get; } = new PBEAlgorithmName("PBEwithSHAand40BitRC4", PkcsObjectIdentifiers.PbeWithShaAnd40BitRC4);

        #endregion Static properties

        #region Properties

        private readonly string _name;
        private readonly DerObjectIdentifier _oid;

        /// <summary>
        /// Gets this algorithm's name.
        /// </summary>
        public string Name => _name;

        internal DerObjectIdentifier Oid => _oid;

        #endregion Properties

        #region Construction

        internal PBEAlgorithmName(string name, DerObjectIdentifier oid)
        {
            _name = name;
            _oid = oid;
        }

        #endregion Construction

        /// <summary>
        /// Gets all algorithm names of the storage.
        /// </summary>
        /// <returns></returns>
        public static PBEAlgorithmName[] GetNames()
        {
            return new PBEAlgorithmName[]
            {
                PBEwithSHAand128BitRC2CBC,
                PBEwithSHAand128BitRC4,
                PBEwithSHAand2KeyDESedeCBC,
                PBEwithSHAand3KeyDESedeCBC,
                PBEwithSHAand40BitRC2CBC,
                PBEwithSHAand40BitRC4,
            };
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(PBEAlgorithmName other)
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