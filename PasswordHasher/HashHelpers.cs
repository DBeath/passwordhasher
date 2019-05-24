using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Linq;

namespace PasswordHasher
{
    public static class HashHelpers
    {
        /// <summary>
        /// Regex for matching SHA256 hashes.
        /// </summary>
        private readonly static Regex sha256Regex = new Regex(@"^[A-F0-9]{64}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        /// <summary>
        /// Regex for matching SHA512 hashes.
        /// </summary>
        private readonly static Regex sha512Regex = new Regex(@"^[A-F0-9]{128}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>
        /// Hash the password with different algorithms depending on the HashVersion, and optionally append the version string.
        /// Defaults to using Bcrypt, and appends the version string by default.
        /// This method should only be used for testing, and generation of the initial intermediate hashes.
        /// If version is HashVersion.SHA256, then input MUST be an SHA256 hash of the original password.
        /// </summary>
        /// <param name="input">String to hash</param>
        /// <param name="version">HashVersion to use for hashing</param>
        /// <param name="addVersion">Append the version string to the hash. Defaults true</param>
        /// <returns>Hashed string with appended version</returns>
        public static string CreateHashWithVersion(string input, HashVersionEnum version = HashVersionEnum.Bcrypt, bool addVersion = true)
        {
            string hash;
            switch (version)
            {
                case HashVersionEnum.SHA256:
                    // Use original SHA256 hashing.
                    hash = CreateSHA256Hash(input);
                    break;
                case HashVersionEnum.Intermediate_SHA256_Bcrypt:
                    // Use intermediate hashing algorithm.
                    // The input MUST be an SHA256 hash of the original password.
                    hash = CreateBcryptHash(input);
                    break;
                case HashVersionEnum.Bcrypt:
                default:
                    // Otherwise we always want to hash with Bcrypt.
                    hash = CreateBcryptHash(input);
                    version = HashVersionEnum.Bcrypt;
                    break;
            }
            // Optionally append Hash Version to hashed Password.
            if (addVersion)
            {
                hash += CreateHashVersionString(version);
            }
            return hash;
        }

        /// <summary>
        /// Create an SHA256 hash of a string. Do not use for further password hashing.
        /// </summary>
        /// <param name="input">String to hash</param>
        /// <returns>SHA256 string</returns>
        public static string CreateSHA256Hash(string input)
        {
            SHA256 sha256 = SHA256.Create();
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            byte[] hash = sha256.ComputeHash(bytes);
            return GetStringFromHash(hash);
        }

        /// <summary>
        /// Create an SHA512 hash of a string. Do not use for further password hashing.
        /// </summary>
        /// <param name="input">String to hash</param>
        /// <returns>SHA512 string</returns>
        public static string CreateSHA512Hash(string input)
        {
            SHA512 sha512 = SHA512.Create();
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            byte[] hash = sha512.ComputeHash(bytes);
            return GetStringFromHash(hash);
        }

        /// <summary>
        /// Convert bytes hash to string.
        /// </summary>
        /// <param name="hash"></param>
        /// <returns></returns>
        private static string GetStringFromHash(byte[] hash)
        {
            var result = new StringBuilder();
            foreach (var t in hash)
            {
                result.Append(t.ToString("X2"));
            }
            return result.ToString();
        }

        /// <summary>
        /// Create a Bcrypt Hash of a string.
        /// Wraps Bcrypt.HashPassword for consistency.
        /// </summary>
        /// <param name="input">String to hash</param>
        /// <returns>Bcrypt Hashed string</returns>
        public static string CreateBcryptHash(string input, int workfactor = 12)
        {
            return BCrypt.Net.BCrypt.HashPassword(input, workFactor: workfactor);
        }

        /// <summary>
        /// Checks that a string might be a valid SHA256 hash.
        /// </summary>
        /// <param name="input">String to check</param>
        /// <returns>True if exact match</returns>
        public static bool MatchesSHA256(string input)
        {
            return sha256Regex.IsMatch(input);
        }

        /// <summary>
        /// Checks that a string might be a valid SHA512 hash.
        /// </summary>
        /// <param name="input">String to check</param>
        /// <returns>True if exact match</returns>
        public static bool MatchesSHA512(string input)
        {
            return sha512Regex.IsMatch(input);
        }

        /// <summary>
        /// Parses a Hashed Password string for a Hash Version and the original Password Hash.
        /// Returns the split original Password Hash and the Hash Version as a Tuple.
        /// A Hash Version is a $ symbol followed by a number, appended to the Password Hash. e.g. "$1".
        /// SHA256 is returned as the default Hash Version, unless the Hash has a valid Bcrypt prefix.
        /// </summary>
        /// <param name="hashedPassword">A hashed password string, possibly including appended version</param>
        /// <returns>Tuple of original hashed password with appended version string removed, and HashVersion enum</returns>
        public static Tuple<string, HashVersionEnum> GetHashVersion(string hashedPassword)
        {
            // Use Unknown as the default HashVersion.
            HashVersionEnum version = HashVersionEnum.Unknown;
            string passwordHash = "";

            // If the Hashed Password starts with "$2" then the Password has already been encrypted with Bcrypt.
            // Therefore we will set the version to Bcrypt in case the Hashed Password doesn't have a version string, or an invalid string.
            if (hashedPassword.StartsWith("$2"))
            {
                version = HashVersionEnum.Bcrypt;
            }
            // Else, we check if the Hashed Password matches the SHA256 regex.
            // Again, we set the version to SHA256 in case the Hashed Password doesn't have a version string, or an invalid string.
            else if (MatchesSHA256(hashedPassword))
            {
                version = HashVersionEnum.SHA256;
            }

            // Our custom hash version will be a single character after the last $ symbol.
            // The $ symbol is the designated delimiter between sections in a hash string.
            int lastDollarSignIndex = hashedPassword.LastIndexOf('$');
            string versionString = hashedPassword.Substring(lastDollarSignIndex + 1);

            // If the versionString has a length of 1, then it should be our custom hash version.
            if (versionString.Length == 1)
            {
                // Safely parse the version number into a HashVersion enum.
                TryParseHashVersion(versionString, ref version);
            }

            // Get a count of all $ symbols in the hashed password.
            int dollarSignCount = hashedPassword.Count(f => f == '$');
            // If there are 4 or more $ symbols, then the password is using Bcrypt, and we have a version string appended.
            // Likewise, if there is only one $ symbol, the password is not hashed with Bcrypt, but we still have a version string.
            // In both cases, we need to return the hashed string without the appended version string.
            if (dollarSignCount >= 4 || dollarSignCount == 1)
            {
                passwordHash = hashedPassword.Substring(0, lastDollarSignIndex);
            }
            else
            {
                passwordHash = hashedPassword;
            }

            return new Tuple<string, HashVersionEnum>(passwordHash, version);
        }

        /// <summary>
        /// Parse a version string into a HashVersion Enum. The version string should be an integer as string.
        /// If parsing fails, the referenced HashVersion will stay unchanged.
        /// </summary>
        /// <param name="versionString">Version of password hash.</param>
        /// <param name="hashVersion">Current HashVersion</param>
        /// <returns>HashVersion enum</returns>
        public static void TryParseHashVersion(string versionString, ref HashVersionEnum hashVersion)
        {
            // 0 is both the default int value and a HashVersion with value "Unknown", so use 0 as default.
            int intVersion = 0;
            // We're using int.Parse inside a Try/Catch instead of int.TryParse because the
            // build tool is failing to build code with int.TryParse.
            try
            {
                intVersion = int.Parse(versionString);
            }
            // If we catch an error, then the version is obviously invalid, so return false.
            catch
            {
                return;
            }

            // Check that the version is a valid HashVersion, and return false if not.
            // We use Enum.IsDefined because Enum.TryParse returns true for any numeric value.
            // https://stackoverflow.com/questions/6741649/enum-tryparse-returns-true-for-any-numeric-values
            bool isDefined = Enum.IsDefined(typeof(HashVersionEnum), intVersion);
            if (!isDefined)
            {
                return;
            }

            // intVersion is valid, so cast to HashVersion and return true.
            hashVersion = (HashVersionEnum)intVersion;
        }

        /// <summary>
        /// Creates a HashVersion string with $ sign. e.g. "$1", "$2"
        /// </summary>
        /// <param name="version">HashVersion enum</param>
        /// <returns>HashVersion string</returns>
        public static string CreateHashVersionString(HashVersionEnum version)
        {
            return "$" + (int)version;
        }
    }
}
