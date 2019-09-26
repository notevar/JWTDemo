using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JWTDemo
{
    class Program
    {
        private static readonly string secret = "123";

        static void Main(string[] args)
        {
            string exp = GetTimeStamp(DateTime.Now.AddHours(1));
            string jwtHeader = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            string jwtPlayload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}";

            string headerBase64Url = Base64UrlEncode(jwtHeader);
            string jwtPlayloadBase64Url = Base64UrlEncode(jwtPlayload);
            string signature = HMACSHA256(headerBase64Url + "." + jwtPlayloadBase64Url, secret);
            string jwtStr = headerBase64Url + "." + jwtPlayloadBase64Url + "." + signature;
            //验证手动生成的Token
            DecoderToken(jwtStr);

            //JWT生成的Token
            var jwt1 = JwtEncoderToken(exp);
            //JWT Token验证
            JwtDecoderToken(jwt1);
            Console.ReadLine();
        }



        private static string HMACSHA256(string message, string key)
        {
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(key);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
              
                string hashresult = BitConverter.ToString(hashmessage).Replace("-", "").ToLower();
                return hashresult;
            }
        }

        /// <summary>
        /// Base64编码
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        private static string Base64UrlEncode(string str)
        {
            byte[] encodedBytes = Encoding.UTF8.GetBytes(str);
            string base64EncodedText = Convert.ToBase64String(encodedBytes);
            base64EncodedText = base64EncodedText
                .Replace("=", String.Empty)
                .Replace('+', '-')
                .Replace('/', '_');
            return base64EncodedText;

        }


        /// <summary>
        /// Base64解码
        /// </summary>
        /// <param name="secureUrlBase64">Base64编码字符串安全的URL.</param>
        /// <returns>Cadena de texto decodificada.</returns>
        public static string Base64UrlDecode(string secureUrlBase64)
        {
            secureUrlBase64 = secureUrlBase64.Replace('-', '+').Replace('_', '/');
            switch (secureUrlBase64.Length % 4)
            {
                case 2:
                    secureUrlBase64 += "==";
                    break;
                case 3:
                    secureUrlBase64 += "=";
                    break;
            }
            var bytes = Convert.FromBase64String(secureUrlBase64);
            return Encoding.UTF8.GetString(bytes);
        }

        private static string GetTimeStamp(DateTime dt)
        {
            DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(new System.DateTime(1970, 1, 1, 0, 0, 0, 0));
            DateTime nowTime = dt;
            long unixTime =
                (long)System.Math.Round((nowTime - startTime).TotalMilliseconds, MidpointRounding.AwayFromZero);
            return unixTime.ToString();
        }

        /// <summary>
        /// JWT加密
        /// </summary>
        /// <param name="exp"></param>
        /// <returns></returns>
        public static string JwtEncoderToken(string exp)
        {
            //IDateTimeProvider provider = new UtcDateTimeProvider();
            //var now = provider.GetNow();

            //var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); // or use JwtValidator.UnixEpoch
            //var secondsSinceEpoch = Math.Round((now - unixEpoch).TotalSeconds);

            var payload = new Dictionary<string, object>
            {
                {"sub", "1234567890"},
                {"name", "John Doe"},
                {"iat", 1516239022}
            };

            IJwtAlgorithm algorithm = new HMACSHA256Algorithm();

            IJsonSerializer serializer = new JsonNetSerializer();

            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();

            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            string jwtStr = encoder.Encode(payload, secret);

            return jwtStr;
        }



        /// <summary>
        /// JWT解密
        /// </summary>
        /// <param name="exp"></param>
        /// <returns></returns>
        public static void JwtDecoderToken(string token)
        {
            try
            {
                Console.WriteLine($"JWT生成的Token{token}解密：");
                IJsonSerializer serializer = new JsonNetSerializer();
                IDateTimeProvider provider = new UtcDateTimeProvider();
                IJwtValidator validator = new JwtValidator(serializer, provider);
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder);

                var json = decoder.Decode(token, secret, verify: true);
                Console.WriteLine(json);
            }
            catch (TokenExpiredException)
            {
                Console.WriteLine("Token has expired");
            }
            catch (SignatureVerificationException)
            {
                Console.WriteLine("Token has invalid signature");
            }
        }


        /// <summary>
        /// JWT手动解密
        /// </summary>
        /// <param name="token">token</param>
        /// <param name="verify">是否验证签名</param>
        public static void DecoderToken(string token, bool verify = true)
        {
            try
            {
                Console.WriteLine($"手动生成的Token{token}解密：");
                var array = token?.Split('.');
                if (array.Length != 3)
                {
                    Console.WriteLine("Token Incorrect format");
                }
                else
                {
                    string jwtHeader = Base64UrlDecode(array[0]);
                    string jwtPlayload = Base64UrlDecode(array[1]);

                    if (verify)
                    {
                        var sign = HMACSHA256($"{array[0]}.{array[1]}", secret);
                        if (sign == array[2])
                        {
                            //过期时间验证
                            Console.WriteLine($"Header:{jwtHeader}");
                            Console.WriteLine($"Playload:{jwtPlayload}");
                        }
                        else
                        {
                            Console.WriteLine("Token has invalid signature");
                        }
                    }
                    
                }
            }
            catch (TokenExpiredException)
            {
                Console.WriteLine("Token has expired");
            }
            catch (SignatureVerificationException)
            {
                Console.WriteLine("Token has invalid signature");
            }
        }
    }


}
