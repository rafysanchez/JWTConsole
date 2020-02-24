using JWT;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Serializers;
using System;
using System.Collections.Generic;

namespace JWTConsole
{
    class Program
    {
        /// <summary>
        /// geração e uso do token jwt
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            const string secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";

            #region gerar token
            //https://github.com/jwt-dotnet/jwt
            // caminho 1
            var payload = new Dictionary<string, object>
                {
                    { "claim1", 0 },
                    { "claim2", "claim2-value" }
                };


            IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var token1 = encoder.Encode(payload, secret);
            Console.WriteLine(token1);

            //******************************************************************

            var token = new JwtBuilder()
                .WithAlgorithm(new HMACSHA256Algorithm())
                .WithSecret(secret)
                .AddClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
                .AddClaim("sub", "sub-value")
                .AddClaim("iss", "iss-value")
                .AddClaim("aud", "aud-value")
                .AddClaim("IdUsuario", "1212121212")
                .Build();

            Console.WriteLine(token);
            #endregion


            #region Analisar Token - avaliar
            // metodo 1

            const string token3 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
            const string secret2 = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";

            try
            {
                IJsonSerializer serializer1 = new JsonNetSerializer();
                IDateTimeProvider provider1 = new UtcDateTimeProvider();
                IJwtValidator validator1 = new JwtValidator(serializer1, provider1);
                IBase64UrlEncoder urlEncoder1 = new JwtBase64UrlEncoder();
                IJwtDecoder decoder = new JwtDecoder(serializer, validator1, urlEncoder1);

                var json = decoder.Decode(token3, secret2, verify: true);
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

            // método 2
            //********************************************************************
            try
            {
                var json = new JwtBuilder()
                    .WithSecret(secret2)
                    .MustVerifySignature()
                    .Decode(token3);
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

            #endregion





        }
    }
}
