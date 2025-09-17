# Repository Guidelines

## Project Structure & Module Organization
Source lives under `src`, split between the generator (`src/Generation`), manually curated bindings (`src/Libs`), extension helpers (`src/Extensions`), and runnable samples (`src/Samples`). Tests live in `src/Tests`, with native scaffolding in `src/Native` and shared fixtures under `src/Tests/Shared`. Generation and maintenance scripts sit in `scripts`, while `ext/gir-files` provides the checked-in introspection metadata that feeds the toolchain. Use `docs/` for extended architecture and contribution notes.

## Build, Test, and Development Commands
- `dotnet fsi GenerateLibs.fsx` (from `scripts/`): regenerate bindings from the latest GIR files. Pass `GirTest-0.1.gir` to include the native test shim.
- `dotnet build GirCore.Libs.slnf` (from `src/`): compile the managed libraries without native test dependencies.
- `dotnet fsi CleanLibs.fsx` (from `scripts/`): wipe generated artifacts under `src/Libs`.
- `dotnet test GirCore.sln` (from `src/`): execute the full test suite; add `--filter TestCategory=IntegrationTest` to mirror CI’s gated run.
- `dotnet format GirCore.sln --no-restore --verify-no-changes` (from `src/`): ensure formatting matches the enforced style, excluding generated files.

## Coding Style & Naming Conventions
Adopt standard C# conventions: four-space indentation, braces on new lines, explicit access modifiers, and object initializers for clarity. Use `PascalCase` for types and public/protected members, `camelCase` for parameters, and `_camelCase` for private fields; avoid abbreviations and Hungarian notation. Favor `var` when the assignment makes the type obvious. Partial classes should be split as `ClassName.Part.ext.cs`, with external implementations grouped via regions. Run `dotnet format` before submitting to catch spacing or analyzer violations skipped for generated files.

## Testing Guidelines
MSTest drives unit and integration coverage, with `AwesomeAssertions` for fluent expectations. Place new tests beside the target library under `src/Tests/Libs/<Library>.Tests` or generator logic in `src/Tests/Generation`. Name classes `<Subject>Tests` and tag methods with `[TestMethod]`, adding `TestCategory` (`UnitTest`, `IntegrationTest`) so CI filters behave. Regenerate the `GirTest` native shim (`dotnet fsi GenerateGirTestLib.fsx`) before scenarios that rely on the C harness, and keep fuzzing artifacts isolated under `src/Tests/Fuzzing`.

## Commit & Pull Request Guidelines
Write imperative, present-tense commit subjects around 70 characters (e.g., “Fix SourceFunc fuzzer defaults”) and limit body text to actionable reasoning. Group changes logically so reviewers can trace generator updates separately from manual bindings. Before opening a PR, ensure `dotnet format` and the relevant `dotnet test` invocations pass locally, update docs or samples impacted by API shifts, and link the tracking issue or discussion. PR descriptions should summarize the intent, outline testing performed, and include screenshots when UI samples change.
