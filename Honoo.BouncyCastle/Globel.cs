namespace Honoo.BouncyCastle
{
    internal static class Global
    {
        /// <summary>
        /// Control global size max value to 65536 or 2147483640. Must be set at program initialization.
        /// </summary>
        internal static int SizeMax { get; } = 65536;
    }
}