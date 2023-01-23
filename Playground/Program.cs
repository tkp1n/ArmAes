using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using ArmAes;
using ByteSizeLib;

internal class Program
{
    public static void Main(string[] args)
    {
        var gcmKey = new AesKey(RandomNumberGenerator.GetBytes(32));
        var xtsKey = new XtsKey(RandomNumberGenerator.GetBytes(64));
        var inetBlock = RandomNumberGenerator.GetBytes(1500);
        var hddBlock = RandomNumberGenerator.GetBytes(4096);
        var gcmIv = RandomNumberGenerator.GetBytes(12);
        var iv = RandomNumberGenerator.GetBytes(16);
        var tag = RandomNumberGenerator.GetBytes(16);

        while (true)
        {
            var end = DateTime.UtcNow + TimeSpan.FromSeconds(1);
            long gcmCtr = 0;
            do
            {
                Gcm.EncryptGcm(
                    inetBlock,
                    inetBlock,
                    ReadOnlySpan<byte>.Empty,
                    gcmIv,
                    tag,
                    gcmKey
                );
                gcmCtr++;
            } while (DateTime.UtcNow < end);

            end = DateTime.UtcNow + TimeSpan.FromSeconds(1);
            long ocbCtr = 0;
            do
            {
                Ocb.EncryptOcb(
                    inetBlock,
                    inetBlock,
                    ReadOnlySpan<byte>.Empty,
                    iv,
                    tag,
                    gcmKey
                );
                ocbCtr++;
            } while (DateTime.UtcNow < end);

            end = DateTime.UtcNow + TimeSpan.FromSeconds(1);
            long xtsCtr = 0;
            do
            {
                Xts.EncryptXts(
                    hddBlock,
                    hddBlock,
                    iv,
                    xtsKey
                );
                xtsCtr++;
            } while (DateTime.UtcNow < end);

            Console.WriteLine($"GCM-256 speed ({inetBlock.Length}-byte frames): {ByteSize.FromBytes(gcmCtr * inetBlock.Length).ToBinaryString()}/s ({ByteSize.FromBytes(gcmCtr * inetBlock.Length * 8).ToBinaryString()}it/s)");
            Console.WriteLine($"OCB-256 speed ({inetBlock.Length}-byte frames): {ByteSize.FromBytes(ocbCtr * inetBlock.Length).ToBinaryString()}/s ({ByteSize.FromBytes(ocbCtr * inetBlock.Length * 8).ToBinaryString()}it/s)");
            Console.WriteLine($"XTS-512 speed ({hddBlock.Length}-byte blocks): {ByteSize.FromBytes(xtsCtr * hddBlock.Length).ToBinaryString()}/s ({ByteSize.FromBytes(xtsCtr * hddBlock.Length * 8).ToBinaryString()}it/s)");
            Console.WriteLine($"Val1: {Convert.ToHexString(inetBlock.AsSpan(0, 16))}");
            Console.WriteLine($"Val2: {Convert.ToHexString(hddBlock.AsSpan(0, 16))}");
            Console.WriteLine($"Tag: {Convert.ToHexString(tag)}");
        }
    }
}