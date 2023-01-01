using BenchmarkDotNet.Attributes;
using static ArmAes.Benchmarks.TestKeys;

namespace ArmAes.Benchmarks;

public class KeyExpansionPerf
{
    [Params(KeyMode.Encrypt, KeyMode.Decrypt, KeyMode.Encrypt | KeyMode.Decrypt)]
    public KeyMode Mode { get; set; }

    [Benchmark]
    public AesKey Aes128BitKeyExpansion() => new(KeyArray128, Mode);

    [Benchmark]
    public AesKey Aes192BitKeyExpansion() => new(KeyArray192, Mode);

    [Benchmark]
    public AesKey Aes256BitKeyExpansion() => new(KeyArray256, Mode);
}
