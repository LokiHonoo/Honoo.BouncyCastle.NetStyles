using Org.BouncyCastle.OpenSsl;

namespace Honoo.BouncyCastle.NetStyles
{
    internal sealed class Password : IPasswordFinder
    {
        private readonly char[] _chars;

        internal Password(string password)
        {
            _chars = password.ToCharArray();
        }

        /// <summary></summary>
        /// <returns></returns>
        public char[] GetPassword()
        {
            return _chars;
        }
    }
}