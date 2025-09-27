using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Generator.Renderer.Internal;

internal static class CallbackCommonHandlerRenderUtils
{
    public static string RenderNativeCallback(GirModel.Callback callback, GirModel.Scope? scope)
    {
        var parameterData = ParameterToManagedExpression.Initialize(callback.Parameters);

        var guardStatement = RenderGuardStatement(callback, scope, parameterData);
        var guardSection = string.IsNullOrEmpty(guardStatement)
            ? string.Empty
            : $"{guardStatement}\n";

        return $@"
NativeCallback = ({GetParameterDefinition(parameterData)}{Error.RenderCallback(callback)}) => {{
{guardSection}    {RenderConvertParameterStatements(parameterData)}
    {RenderCallStatement(callback, parameterData, out var resultVariableName)}
    {RenderPostCallStatements(parameterData)}
    {RenderFreeStatement(scope)}
    {RenderReturnStatement(callback, resultVariableName)}
}};";
    }

    private static string RenderGuardStatement(GirModel.Callback callback, GirModel.Scope? scope, IReadOnlyList<ParameterToManagedData> parameterData)
    {
        if (scope is not GirModel.Scope.Notified)
        {
            return string.Empty;
        }

        var guard = new StringBuilder();

        guard.AppendLine("    if (!gch.IsAllocated)");
        guard.AppendLine("    {");

        foreach (var parameter in parameterData)
        {
            if (parameter.IsCallbackDestroyNotify)
                continue;

            if (parameter.IsCallbackUserData)
                continue;

            if (parameter.IsArrayLengthParameter)
                continue;

            if (parameter.Parameter.Direction == GirModel.Direction.Out)
                guard.AppendLine($"        {parameter.GetSignatureName()} = default;");
        }

        if (callback.Throws)
            guard.AppendLine("        error = default;");

        if (callback.ReturnType.AnyType.Is<GirModel.Void>())
            guard.AppendLine("        return;");
        else
            guard.AppendLine("        return default;");

        guard.Append("    }");

        return guard.ToString();
    }

    private static string GetParameterDefinition(IReadOnlyList<ParameterToManagedData> parameterData)
    {
        var parameters = new List<string>();

        foreach (var parameter in parameterData)
        {
            var type = CallbackParameters.GetNullableTypeName(parameter.Parameter);
            var direction = CallbackParameters.GetDirection(parameter.Parameter);
            parameters.Add($"{direction}{type} {parameter.GetSignatureName()}");
        }

        return parameters.Join(", ");
    }

    private static string RenderConvertParameterStatements(IEnumerable<ParameterToManagedData> data)
    {
        var call = new StringBuilder();

        foreach (var p in data)
        {
            if (p.IsCallbackDestroyNotify)
                continue;

            if (p.IsCallbackUserData)
                continue;

            if (p.IsArrayLengthParameter)
                continue;

            call.AppendLine(p.GetExpression());
        }

        return call.ToString();
    }

    private static string RenderCallStatement(GirModel.Callback callback, IEnumerable<ParameterToManagedData> parameterData, out string resultVariableName)
    {
        resultVariableName = "managedCallbackResult";

        var parameters = new List<string>();
        foreach (var p in parameterData)
        {
            if (p.IsArrayLengthParameter)
                continue;

            if (p.IsCallbackUserData)
                continue;

            if (p.IsCallbackDestroyNotify)
                continue;

            if (p.IsGLibErrorParameter)
                continue;

            parameters.Add(p.GetCallName());
        }

        var call = new StringBuilder();

        if (!callback.ReturnType.AnyType.Is<GirModel.Void>())
            call.AppendLine($"{Public.ReturnTypeRendererCallback.Render(callback.ReturnType)} {resultVariableName} = default;");

        if (callback.Throws || parameterData.Any(x => x.IsGLibErrorParameter))
            call.AppendLine("try { ");

        if (!callback.ReturnType.AnyType.Is<GirModel.Void>())
            call.AppendLine($"{resultVariableName} = managedCallback({parameters.Join(", ")});");
        else
            call.AppendLine($"managedCallback({parameters.Join(", ")});");

        if (callback.Throws || parameterData.Any(x => x.IsGLibErrorParameter))
        {
            call.AppendLine("error = IntPtr.Zero;");
            call.AppendLine("} catch(Exception ex) {");
            call.AppendLine("error = GLib.Internal.Error.NewLiteralUnowned(1, 1, GLib.Internal.NonNullableUtf8StringUnownedHandle.Create(ex.Message)).DangerousGetHandle();");
            call.AppendLine("}");
        }

        return call.ToString();
    }

    private static string RenderPostCallStatements(IEnumerable<ParameterToManagedData> data)
    {
        var call = new StringBuilder();

        foreach (var p in data)
        {
            var postCallExpression = p.GetPostCallExpression();
            if (postCallExpression is not null)
                call.AppendLine(postCallExpression);
        }

        return call.ToString();
    }

    private static string RenderFreeStatement(GirModel.Scope? scope)
    {
        return scope == GirModel.Scope.Async
            ? "gch.Free();"
            : string.Empty;
    }

    private static string RenderReturnStatement(GirModel.Callback callback, string returnVariableName)
    {
        return callback.ReturnType.AnyType.Is<GirModel.Void>()
            ? string.Empty
            : $"return {ReturnTypeToNativeExpression.Render(callback.ReturnType, returnVariableName)};";
    }
}
