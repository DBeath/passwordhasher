using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PasswordHasher.Tests
{
    [TestClass]
    public class PasswordHasherTests
    {
        public class User { }

        private readonly PasswordHasher<User> passwordHasher;
        private readonly User user = new User();

        public PasswordHasherTests()
        {
            passwordHasher = new PasswordHasher<User>();
        }

        [TestMethod]
        public void Test_CreateHashVersionString_ShouldReturnValidString()
        {
            var result1 = HashHelpers.CreateHashVersionString(HashVersionEnum.SHA256);
            result1.Should().Be("$1");

            var result2 = HashHelpers.CreateHashVersionString(HashVersionEnum.Intermediate_SHA256_Bcrypt);
            result2.Should().Be("$2");

            var result3 = HashHelpers.CreateHashVersionString(HashVersionEnum.Bcrypt);
            result3.Should().Be("$3");
        }

        [TestMethod]
        public void Test_GetHashVersion_ShouldReturnHashAndBcryptVersion_FromValidBcryptWithVersion()
        {
            var password = "$2$10$asdfassdasasfas$3";
            var result = HashHelpers.GetHashVersion(password);
            result.Item1.Should().Be("$2$10$asdfassdasasfas");
            result.Item2.Should().Be(HashVersionEnum.Bcrypt);
        }

        [TestMethod]
        public void Test_GetHashVersion_ShouldReturnHashAndSHA256Version_FromValidSHA256WithoutVersion()
        {
            var password = "ECD71870D1963316A97E3AC3408C9835AD8CF0F3C1BC703527C30265534F75AE";
            var result = HashHelpers.GetHashVersion(password);
            result.Item1.Should().Be("ECD71870D1963316A97E3AC3408C9835AD8CF0F3C1BC703527C30265534F75AE");
            result.Item2.Should().Be(HashVersionEnum.SHA256);
        }

        [TestMethod]
        public void Test_GetHashVersion_ShouldReturnHashAndBcryptVersion_FromValidBcryptWithoutVersion()
        {
            var password = "$2$10$asdfassdasasfas";
            var result = HashHelpers.GetHashVersion(password);
            result.Item1.Should().Be("$2$10$asdfassdasasfas");
            result.Item2.Should().Be(HashVersionEnum.Bcrypt);
        }

        [TestMethod]
        public void Test_GetHashVersion_ShouldReturnHashAndIntermediateVersion_FromBcryptWithIntermediateVersion()
        {
            var password = "$2$10$asdfassdasasfas$2";
            var result = HashHelpers.GetHashVersion(password);
            result.Item1.Should().Be("$2$10$asdfassdasasfas");
            result.Item2.Should().Be(HashVersionEnum.Intermediate_SHA256_Bcrypt);
        }

        [TestMethod]
        public void Test_GetHashVersion_ShouldReturnHashAndBcryptVersion_FromBcryptWithInvalidVersion()
        {
            var password = "$2$10$asdfassdasasfas$5";
            var result = HashHelpers.GetHashVersion(password);
            result.Item1.Should().Be("$2$10$asdfassdasasfas");
            result.Item2.Should().Be(HashVersionEnum.Bcrypt);
        }

        [TestMethod]
        public void Test_GetHashVersion_ShouldReturnHashAndBcryptVersion_FromBcryptWithInvalidVersionAsString()
        {
            var password = "$2$10$asdfassdasasfas$version1";
            var result = HashHelpers.GetHashVersion(password);
            result.Item1.Should().Be("$2$10$asdfassdasasfas");
            result.Item2.Should().Be(HashVersionEnum.Bcrypt);
        }

        [TestMethod]
        public void Test_GetHashVersion_ShouldReturnHashAndBcryptVersion_FromBcryptWithMoreThanOneColon()
        {
            // One extra colon
            var password = "$2$10$asdf:asdfasdf$3";
            var result = HashHelpers.GetHashVersion(password);
            result.Item1.Should().Be("$2$10$asdf:asdfasdf");
            result.Item2.Should().Be(HashVersionEnum.Bcrypt);

            // 4 extra colons
            var password2 = "$2$10$asdf:asdf:asdf:asdf:asdf$3";
            var result2 = HashHelpers.GetHashVersion(password2);
            result2.Item1.Should().Be("$2$10$asdf:asdf:asdf:asdf:asdf");
            result2.Item2.Should().Be(HashVersionEnum.Bcrypt);
        }

        [TestMethod]
        public void Test_GetHashVersion_ShouldReturnEmptyStringAndUnknownVersion_FromEmptyString()
        {
            var password = "";
            var result = HashHelpers.GetHashVersion(password);
            result.Item1.Should().Be("");
            result.Item2.Should().Be(HashVersionEnum.Unknown);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnSuccessRehashNeeded_FromSHA256WithoutVersion_ValidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.SHA256, addVersion: false);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, password);
            verified.Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnSuccessRehashNeeded_FromSHA256WithVersion_ValidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.SHA256);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, password);
            verified.Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromSHA256WithoutVersion_InvalidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.SHA256, addVersion: false);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, "test12345");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromSHA256WithVersion_InvalidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.SHA256);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, "test12345");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromSHA256WithWrongVersion_ValidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.SHA256, addVersion: false);
            // Wrong version for hash
            hashed = hashed + "$3";

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, password);
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnSuccessRehashNeeded_FromBcryptIntermediateWithVersion_ValidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(HashHelpers.CreateSHA256Hash(password), HashVersionEnum.Intermediate_SHA256_Bcrypt);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, password);
            verified.Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromBcryptIntermediateWithoutVersion_ValidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(HashHelpers.CreateSHA256Hash(password), HashVersionEnum.Intermediate_SHA256_Bcrypt, addVersion: false);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, password);
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromBcryptIntermediateWithoutVersion_InvalidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(HashHelpers.CreateSHA256Hash(password), HashVersionEnum.Intermediate_SHA256_Bcrypt, addVersion: false);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, "test12345");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromBcryptIntermediateWithVersion_InvalidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(HashHelpers.CreateSHA256Hash(password), HashVersionEnum.Intermediate_SHA256_Bcrypt);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, "test12345");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnSuccess_FromBcryptWithVersion_ValidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.Bcrypt);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, password);
            verified.Should().Be(PasswordVerificationResult.Success);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnSuccess_FromBcryptWithoutVersion_ValidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.Bcrypt, addVersion: false);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, password);
            verified.Should().Be(PasswordVerificationResult.Success);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromBcryptWithVersion_InvalidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.Bcrypt);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, "test12345");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromBcryptWithoutVersion_InvalidPassword()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.Bcrypt, addVersion: false);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, "test12345");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromEmptyHashString()
        {
            var verified = passwordHasher.VerifyHashedPassword(user, "", "test1234");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromNullHashString()
        {
            var verified = passwordHasher.VerifyHashedPassword(user, null, "test1234");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromDeletedHashString()
        {
            var verified = passwordHasher.VerifyHashedPassword(user, "$deleted$", "test1234");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromWhitespaceHashString()
        {
            var verified = passwordHasher.VerifyHashedPassword(user, "   ", "test1234");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromNullPasswordString()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateSHA256Hash(password);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, null);
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromEmptyPasswordString()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateSHA256Hash(password);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, "");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_VerifyHashedPassword_ShouldReturnFailed_FromWhitespacePasswordString()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateSHA256Hash(password);

            var verified = passwordHasher.VerifyHashedPassword(user, hashed, "   ");
            verified.Should().Be(PasswordVerificationResult.Failed);
        }

        [TestMethod]
        public void Test_CreateHashWithVersion_ShouldReturnSHA256_FromSHA256HashVersion()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.SHA256);
            var version = HashHelpers.GetHashVersion(hashed);
            version.Item2.Should().Be(HashVersionEnum.SHA256);
        }

        [TestMethod]
        public void Test_CreateHashWithVersion_ShouldReturnIntermediate_FromBcryptIntermediateHashVersion()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.Intermediate_SHA256_Bcrypt);
            var version = HashHelpers.GetHashVersion(hashed);
            version.Item2.Should().Be(HashVersionEnum.Intermediate_SHA256_Bcrypt);
        }

        [TestMethod]
        public void Test_CreateHashWithVersion_ShouldReturnBcrypt_FromBcryptHashVersion()
        {
            var password = "test123";
            var hashed = HashHelpers.CreateHashWithVersion(password, HashVersionEnum.Bcrypt);
            var version = HashHelpers.GetHashVersion(hashed);
            version.Item2.Should().Be(HashVersionEnum.Bcrypt);
        }

        [TestMethod]
        public void Test_MatchesSHA256_ShouldCorrectlyMatch()
        {
            HashHelpers.MatchesSHA256("ECD71870D1963316A97E3AC3408C9835AD8CF0F3C1BC703527C30265534F75AE").Should().BeTrue();
            HashHelpers.MatchesSHA256("936A185CAAA266BB9CBE981E9E05CB78CD732B0B3280EB944412BB6F8F8F07AF").Should().BeTrue();
            // Contains lowercase
            HashHelpers.MatchesSHA256("936A185CAAA266BB9CBE981E9E05CB78CD732B0B3280EB944412BB6F8F8F07af").Should().BeTrue();
            // Too long
            HashHelpers.MatchesSHA256("936A185CAAA266BB9CBE981E9E05CB78CD732B0B3280EB944412BB6F8F8F07AFA").Should().BeFalse();
            // Too short
            HashHelpers.MatchesSHA256("936A185CAAA266BB9CBE981E9E05CB78CD732B0B3280EB944412BB6F8F8F07A").Should().BeFalse();
            // Invalid characters
            HashHelpers.MatchesSHA256("936A185CAAA266BB9CBE981E9E05CB78CD732B0B3280EB944412BB6F8F8F07A!").Should().BeFalse();
        }
    }
}
