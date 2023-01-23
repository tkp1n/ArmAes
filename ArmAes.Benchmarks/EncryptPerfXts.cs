using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace ArmAes.Benchmarks;

public class EncryptPerfXts
{
    [Benchmark]
    public void ArmAesXts()
    {
        Xts.EncryptXts(input, output, iv, Keys);
    }

    private byte[] input;
    private byte[] iv;
    private byte[] output;
    private byte[] key;

    [Params(128, 256)] public int KeySize { get; set; }
    [Params(4096)] public int DataSize { get; set; }

    private XtsKey Keys => new(key.AsSpan(0, KeySize / 8), key.AsSpan(KeySize / 8));

    [GlobalSetup]
    public void Setup()
    {
        input = RandomNumberGenerator.GetBytes(DataSize);
        output = RandomNumberGenerator.GetBytes(DataSize);
        iv = RandomNumberGenerator.GetBytes(64 / 8);
        key = RandomNumberGenerator.GetBytes(KeySize / 8 * 2);
    }
}