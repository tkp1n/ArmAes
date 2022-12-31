using System;
using System.IO;
using Xunit;
using Xunit.Abstractions;

namespace ArmAes.Tests;

// https://www.rfc-editor.org/rfc/rfc7253.html
public class Rfc7253Tests
{
    private readonly ITestOutputHelper _output;

    public Rfc7253Tests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Theory]
    [InlineData("BBAA99887766554433221100", "", "", "785407BFFFC8AD9EDCC5520AC9111EE6")]
    [InlineData("BBAA99887766554433221101", "0001020304050607", "0001020304050607", "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009")]
    [InlineData("BBAA99887766554433221102", "0001020304050607", "", "81017F8203F081277152FADE694A0A00")]
    [InlineData("BBAA99887766554433221103", "", "0001020304050607", "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9")]
    [InlineData("BBAA99887766554433221104", "000102030405060708090A0B0C0D0E0F", "000102030405060708090A0B0C0D0E0F", "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358")]
    [InlineData("BBAA99887766554433221105", "000102030405060708090A0B0C0D0E0F", "", "8CF761B6902EF764462AD86498CA6B97")]
    [InlineData("BBAA99887766554433221106", "", "000102030405060708090A0B0C0D0E0F", "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D")]
    [InlineData("BBAA99887766554433221107", "000102030405060708090A0B0C0D0E0F1011121314151617", "000102030405060708090A0B0C0D0E0F1011121314151617", "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F")]
    [InlineData("BBAA99887766554433221108", "000102030405060708090A0B0C0D0E0F1011121314151617", "", "6DC225A071FC1B9F7C69F93B0F1E10DE")]
    [InlineData("BBAA99887766554433221109", "", "000102030405060708090A0B0C0D0E0F1011121314151617", "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF")]
    [InlineData("BBAA9988776655443322110A", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240")]
    [InlineData("BBAA9988776655443322110B", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "", "FE80690BEE8A485D11F32965BC9D2A32")]
    [InlineData("BBAA9988776655443322110C", "", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF")]
    [InlineData("BBAA9988776655443322110D", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60")]
    [InlineData("BBAA9988776655443322110E", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "", "C5CD9D1850C141E358649994EE701B68")]
    [InlineData("BBAA9988776655443322110F", "", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479")]
    public void Test1(string N, string A, string P, string C)
    {
        var key = new AesKey(Convert.FromHexString("000102030405060708090A0B0C0D0E0F"), KeyMode.Encrypt | KeyMode.Decrypt);

        Span<byte> nonce = Convert.FromHexString(N);
        Span<byte> addt = Convert.FromHexString(A);
        Span<byte> pt = Convert.FromHexString(P);
        Span<byte> verifyPt = new byte[pt.Length];
        Span<byte> ct = Convert.FromHexString(C[..^(16 * 2)]);
        Span<byte> actualCt = new byte[ct.Length];
        Span<byte> tag = Convert.FromHexString(C[^(2 * 16)..]);
        Span<byte> actualTag = new byte[tag.Length];

        Ocb.EncryptOcb(pt, actualCt, addt, nonce, actualTag, key);
        var res = Ocb.DecryptOcb(ct, verifyPt, addt, nonce, tag, key);

        _output.WriteLine($"PT len  = {pt.Length}");
        _output.WriteLine($"AD len  = {addt.Length}");
        _output.WriteLine($"CT len  = {ct.Length}");
        _output.WriteLine($"tag len = {tag.Length}");

        Assert.True(res);
        Assert.Equal(Convert.ToHexString(pt), Convert.ToHexString(verifyPt));

        Assert.Equal(Convert.ToHexString(ct), Convert.ToHexString(actualCt));
        Assert.Equal(Convert.ToHexString(tag), Convert.ToHexString(actualTag));
    }

    [Theory]
    [InlineData(128, "67E944D23256C5E0B6C61FA22FDF1EA2")]
    [InlineData(192, "F673F2C3E7174AAE7BAE986CA9F29E17")]
    [InlineData(256, "D90EB8E9C977C88B79DD793D7FFA161C")]

    [InlineData(128, "77A3D8E73589158D25D01209")]
    [InlineData(192, "05D56EAD2752C86BE6932C5E")]
    [InlineData(256, "5458359AC23B0CBA9E6330DD")]

    [InlineData(128, "192C9B7BD90BA06A")]
    [InlineData(192, "0066BC6E0EF34E24")]
    [InlineData(256, "7D4EA5D445501CBE")]
    public void Test2(int keylen, string result)
    {
        keylen /= 8;
        var taglen = result.Length / 2;

        var keybuf = new byte[keylen];
        keybuf[keylen - 1] = (byte)(taglen * 8);

        var K = new AesKey(keybuf, KeyMode.Encrypt | KeyMode.Decrypt);

        var c = new byte[0];
        var C = new MemoryStream();
        Span<byte> N = new byte[12];
        var tag = new byte[taglen];

        for (int i = 0; i < 128; i++)
        {
            var S = new byte[i];
            var Sv = new byte[i];
            Random.Shared.NextBytes(Sv);

            // N = num2str(3i+1,96)
            num2str(N, 3 * i + 1);

            // C = C || OCB-ENCRYPT(K,N,S,S)
            c = OcbEncrypt(K, N, S, S, tag);
            C.Write( c);
            Assert.True(OcbDecrypt(K, N, S, c, Sv, tag));
            Assert.Equal(Convert.ToHexString(S), Convert.ToHexString(Sv));
            Random.Shared.NextBytes(Sv);

            // N = num2str(3i+2,96)
            num2str(N, 3 * i + 2);

            // C = C || OCB-ENCRYPT(K,N,<empty string>,S)
            c = OcbEncrypt(K, N, ReadOnlySpan<byte>.Empty, S, tag);
            C.Write(c);
            Assert.True(OcbDecrypt(K, N, ReadOnlySpan<byte>.Empty, c, Sv, tag), i.ToString());
            Assert.Equal(Convert.ToHexString(S), Convert.ToHexString(Sv));
            Random.Shared.NextBytes(Sv);

            // N = num2str(3i+3,96)
            num2str(N, 3 * i + 3);

            // C = C || OCB-ENCRYPT(K,N,S,<empty string>)
            c = OcbEncrypt(K, N, S, ReadOnlySpan<byte>.Empty, tag);
            C.Write(c);
            Assert.True(OcbDecrypt(K, N, S, c, Span<byte>.Empty, tag));
        }

        // N = num2str(385,96)
        num2str(N, 385);

        // OCB-ENCRYPT(K,N,C,<empty string>)
        c = C.ToArray();
        var final = OcbEncrypt(K, N, c, ReadOnlySpan<byte>.Empty, tag);
        Assert.True(OcbDecrypt(K, N, c, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, final));
        Assert.Equal(result, Convert.ToHexString(final));
    }

    private static void num2str(Span<byte> N, int i)
    {
        N.Clear();
        N[11] = (byte)(i & 0xFF);
        N[10] = (byte)(i >> 8);
    }

    private static byte[] OcbEncrypt(
        AesKey key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ad,
        ReadOnlySpan<byte> plaintext,
        Span<byte> tag)
    {
        var ciphertext = new byte[plaintext.Length + tag.Length];
        Ocb.EncryptOcb(
            input: plaintext,
            output: ciphertext,
            addt: ad,
            iv: nonce,
            tag: tag,
            key: key);

        tag.CopyTo(ciphertext.AsSpan(plaintext.Length));
        return ciphertext;
    }

    private static bool OcbDecrypt(
        AesKey key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ad,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> plaintext,
        ReadOnlySpan<byte> tag)
    {
        var ct = ciphertext.Length == 0 ? ReadOnlySpan<byte>.Empty : ciphertext[..^tag.Length];
        return Ocb.DecryptOcb(ct, plaintext, ad, nonce, tag, key);
    }
}
