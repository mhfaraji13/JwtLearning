using System.Security.Cryptography;
using System.Text;
using System.Text.Json;


namespace JwtLearning
{
    public class Program
    {
        static void Main(string[] args)
        {


            //==================================================================
            //Create JWT Token - Header step by step
            //==================================================================
            var header = new
            {
                alg = "HS256",
                typ = "JWT"
            };

            var headerJson = JsonSerializer.Serialize(header);

            var headerBytes = Encoding.UTF8.GetBytes(headerJson);
            var headerBase64 = Convert.ToBase64String(headerBytes);

            var headerBase64Url = headerBase64
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');

            //============================================================================
            //Create Payload - step by step 
            //============================================================================

            var payload = new
            {
                sub = "125",
                name = "Mohammadhossein",
                role = "Admin",
                // when token issuance
                iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                exp = DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds()
            };
            var payloadJson = JsonSerializer.Serialize(payload);
            var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
            var payloadBase64 = Convert.ToBase64String(payloadBytes);

            var payloadBase64Url = payloadBase64
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');

            // Create Signature but for crate signature , first must have secretkey
            // The meaning of Demo is demonstration
            // Signature = HMAC-SHA256(SecretKey,SigningInput)
            //Base64Url(Header).Base64Url(Payload)

            var secretkey = Encoding.UTF8.GetBytes(
                "My-Demo-Secret-Key-For-JWT-2026-!"
                );
            var signingInput = $"{headerBase64Url}.{payloadBase64Url}";
            var signingInputBytes = Encoding.UTF8.GetBytes(signingInput);
            // Create Signature

            var signatureBytes = HMACSHA256.HashData(
                secretkey,
                signingInputBytes
                );

            var signatureBase64 = Convert.ToBase64String(signatureBytes);

            var signatureBase64Url = signatureBase64
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');

            // ok now we create the 3 parts of jwt now wa must connect 3 parts to each other or together

            var jwt = $"{headerBase64Url}.{payloadBase64Url}.{signatureBase64Url}";








            Console.WriteLine(jwt);

            var decodedPayload = DecodeJwtPayloadWithoutLibrary(jwt);
            Console.WriteLine(decodedPayload);
        }

        // decoded the payload of jwt

        public static string DecodeJwtPayloadWithoutLibrary(string jwts)
        {
            var parts = jwts.Split('.');

            if (parts.Length != 3)
            {
                throw new ArgumentException("Invalid Jwt format");
            }

            // Get Payload

            var payloadBase64Url = parts[1];

            var payloadBase64 = payloadBase64Url
                .Replace("-", "+")
                .Replace("_", "/");
            //The Base64 standard divides the output into groups of 4 characters.

            // Restore Padding

            switch (payloadBase64.Length % 4)
            {
                case 2:
                    payloadBase64 += "==";
                    break;
                case 3:
                    payloadBase64 += "=";
                    break;
                case 1:
                    throw new ArgumentException("Invalid Base64Url format");
            }


            var decodedBytes = Convert.FromBase64String(payloadBase64);

            var decodeString = Encoding.UTF8.GetString(decodedBytes);

            return decodeString;

            


            //byte[] decodedBytes = Base64Url.DecodeFromChars(parts[1]);

            //return Encoding.UTF8.GetString(decodedBytes);
        }

    }
}
