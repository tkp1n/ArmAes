using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using static ArmAes.Benchmarks.TestKeys;

namespace ArmAes.Benchmarks;

public class EncryptPerfAead
{
    [Benchmark]
    public void ArmAesOcb()
    {
        Ocb.EncryptOcb(input, output, aad, nonce, tag, AesKey(KeyMode.Encrypt | KeyMode.Decrypt));
    }

    [Benchmark(Baseline = true)]
    public void ArmAesGcm()
    {
        Gcm.EncryptGcm(input, output, aad, nonce, tag, AesKey(KeyMode.Encrypt));
    }

    private AesGcm frameworkGcm;
    private byte[] input;
    private byte[] nonce;
    private byte[] output;
    private byte[] tag;
    private byte[] aad;

    [Params(128, 192, 256)] public int KeySize { get; set; }
    [Params(44, 552, 576, 1500)] public int DataSize { get; set; }
    [Params(0)] public int AadDataSize { get; set; }

    private ReadOnlySpan<byte> KeyBytes
    {
        get
        {
            switch (KeySize)
            {
                case 128: return KeyArray128;
                case 192: return KeyArray192;
                case 256: return KeyArray256;
                default: throw new InvalidDataException();
            }
        }
    }

    private AesKey AesKey(KeyMode mode) => new(KeyBytes, mode);

    [GlobalSetup]
    public void Setup()
    {
        input = new byte[DataSize];
        output = new byte[DataSize];
        aad = new byte[AadDataSize];
        nonce = new byte[12];
        tag = new byte[16];
        var r = new Random(42);
        r.NextBytes(input);
        r.NextBytes(output);
        r.NextBytes(nonce);
        r.NextBytes(aad);
        frameworkGcm = new AesGcm(KeyBytes);
    }
}