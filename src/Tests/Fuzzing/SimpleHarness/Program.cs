using SharpFuzz;

namespace GirCore.Fuzzing;

public static class Program
{
    public static void Main(string[] args)
    {
        Fuzzer.Run(SimpleHarnessFuzzer.Run);
    }
}
