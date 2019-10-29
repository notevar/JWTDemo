using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JWTDemo
{
    class Class1
    {
        public static void Main()
        {
            var header = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
            var claims = "{\"sub\":\"1047986\",\"email\":\"jon.doe@eexample.com\",\"given_name\":\"John\",\"family_name\":\"Doe\",\"primarysid\":\"b521a2af99bfdc65e04010ac1d046ff5\",\"iss\":\"http://example.com\",\"aud\":\"myapp\",\"exp\":1460555281,\"nbf\":1457963281}";

            var b64header = Convert.ToBase64String(Encoding.UTF8.GetBytes(header))
                .Replace('+', '-')
                .Replace('/', '_')
                .Replace("=", "");
            var b64claims = Convert.ToBase64String(Encoding.UTF8.GetBytes(claims))
                .Replace('+', '-')
                .Replace('/', '_')
                .Replace("=", "");

            var payload = b64header + "." + b64claims;
            Console.WriteLine("JWT without sig:    " + payload);

            byte[] key = Convert.FromBase64String("mPorwQB8kMDNQeeYO35KOrMMFn6rFVmbIohBphJPnp4=");
            byte[] message = Encoding.UTF8.GetBytes(payload);

            string sig = Convert.ToBase64String(HashHMAC(key, message))
                .Replace('+', '-')
                .Replace('/', '_')
                .Replace("=", "");

            Console.WriteLine("JWT with signature: " + payload + "." + sig);
        }

        private static byte[] HashHMAC(byte[] key, byte[] message)
        {
            var hash = new HMACSHA256(key);
            return hash.ComputeHash(message);
        }
    }
}
