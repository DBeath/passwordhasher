/*
 * Handles all password hashing and verification.
 *
 * Passwords were originally hashed with SHA256. Bad idea.
 *
 * The following code is designed to handle multiple versions of hashed passwords while
 * user's existing password hashes are rehashed with a more secure algorithm. This code should also work
 * to upgrade the hashing algorithm in the future if necessary.
 *
 * Algorithm is as follows:
 * 1. Rehash all User's passwords, using the existing hash as input to the new hash algorithm.
 * 2. When User logs in, check the version of the current hash.
 * 3. If intermediate hash version, verify password by first hashing the password with the old hash algorithm, and using that as input to new hash algorithm.
 * 4. If User is verified, rehash the input plaintext password with the new hash algorithm, and replace the old hash in the database.
 * 5. On next login, hash version will be the new version, and so User will be verified using only the new hash algorithm.
 *
 * Now using Bcrypt.Net https://github.com/BcryptNet/bcrypt.net
 *
 * Rehashing algorithm from here: https://www.michalspacek.com/upgrading-existing-password-hashes
 * Futher reading: 
 * https://paragonie.com/blog/2016/02/how-safely-store-password-in-2016
 * https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
 * https://veggiespam.com/painless-password-hash-upgrades/
 */

using System;
using BCrypt.Net;
using Microsoft.AspNetCore.Identity;

namespace PasswordHasher
{
    /// <summary>
    /// Hashes and Verifies Passwords
    /// </summary>
    public class PasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
    {
        // Workfactor for new Bcrypt hashes. Higher workfactor = more processing time to create hash.
        // Changing this does not affect verification of current hashes, as the workfactor used is stored in the hash.
        private const int WORKFACTOR = 12;

        /// <summary>
        /// Hash a Password using Bcrypt.
        /// Appends the Hash Version String "$3" (meaning Bcrypt) to the Hash.
        /// </summary>
        /// <param name="password">Password to hash</param>
        /// <returns></returns>
        public string HashPassword(TUser user, string password)
        {
            return HashHelpers.CreateBcryptHash(password, WORKFACTOR) + HashHelpers.CreateHashVersionString(HashVersionEnum.Bcrypt);
        }

        /// <summary>
        /// Verify that a Password matches the hashed Password.
        /// </summary>
        /// <param name="hashedPassword">Hashed Password</param>
        /// <param name="providedPassword">Password to verify against hashed Password</param>
        /// <returns></returns>
        public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
        {
            // Verification should fail if the provided Password is null, empty, or whitespace.
            if (string.IsNullOrEmpty(providedPassword))
            {
                return PasswordVerificationResult.Failed;
            }

            // Verification should fail if the hashed Password is null, empty, whitespace, or the string "$deleted$".
            if (string.IsNullOrEmpty(hashedPassword) || hashedPassword.Trim() == "$deleted$")
            {
                return PasswordVerificationResult.Failed;
            }

            // Get the current Hash Version and the Hashed Password without the version string.
            Tuple<string, HashVersionEnum> result = HashHelpers.GetHashVersion(hashedPassword);
            string currentHash = result.Item1;
            HashVersionEnum hashVersion = result.Item2;

            // Verify the provided Password against the current Hash.
            try
            {
                switch (hashVersion)
                {
                    case HashVersionEnum.Unknown:
                        // We have an invalid or Unknown HashVersion, so we cannot verify the password.
                        // This case should not be hit if we hash our passwords correctly, but should be included as a precaution.
                        return PasswordVerificationResult.Failed;
                    case HashVersionEnum.SHA256:
                        // Use original SHA256 hashing, return SuccessRehashNeeded if valid.
                        return VerifySHA256Hash(providedPassword, currentHash) ? PasswordVerificationResult.SuccessRehashNeeded : PasswordVerificationResult.Failed;
                    case HashVersionEnum.Intermediate_SHA256_Bcrypt:
                        // Use intermediate hashing algorithm, pass SHA256 hash of password as input to Bcrypt.
                        // Return SuccessRehashNeeded if valid.
                        return VerifyBcryptHash(HashHelpers.CreateSHA256Hash(providedPassword), currentHash) ? PasswordVerificationResult.SuccessRehashNeeded : PasswordVerificationResult.Failed;
                    case HashVersionEnum.Bcrypt:
                    default:
                        // Otherwise we always want to verify with Bcrypt by default. Return Success if valid.
                        return VerifyBcryptHash(providedPassword, currentHash) ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
                }
            }
            catch (SaltParseException)
            {
                return PasswordVerificationResult.Failed;
            }
        }

        /// <summary>
        /// Verify a provided text against a Bcrypt hash.
        /// Wraps Bcrypt.Verify for consistency.
        /// </summary>
        /// <param name="text"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        private static bool VerifyBcryptHash(string text, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(text, hash);
        }

        /// <summary>
        /// Verify a provided text against a SHA256 hash.
        /// </summary>
        /// <param name="text"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        private static bool VerifySHA256Hash(string text, string hash)
        {
            return string.Equals(hash, HashHelpers.CreateSHA256Hash(text), StringComparison.OrdinalIgnoreCase);
        }
    }
}