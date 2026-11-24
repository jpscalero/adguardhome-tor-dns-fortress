@{
    # Analizador de PowerShell para CI.
    # Solo los errores bloquean la integración; los avisos se muestran como informacion.
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        'PSAvoidUsingWriteHost',              # la suite es interactiva por diseno
        'PSAvoidUsingInvokeExpression',       # usado en lanzadores VBS
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns',
        'PSAvoidUsingPositionalParameters',
        'PSUseApprovedVerbs',
        'PSProvideCommentHelp',
        'PSAvoidGlobalVars',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSAvoidTrailingWhitespace',
        'PSUseBOMForUnicodeEncodedFile'
    )
}
