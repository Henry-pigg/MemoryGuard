' ============================================================
'  Memory Guard launcher  (no console window)
'  Finds pythonw.exe and starts memory_guard.py silently.
' ============================================================
Option Explicit

Dim fso, sh, base, script, pyw, item, root, sub_, cmd

Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")

base   = fso.GetParentFolderName(WScript.ScriptFullName)
script = base & "\memory_guard.py"

If Not fso.FileExists(script) Then
    MsgBox "memory_guard.py not found in:" & vbCrLf & base, 16, "Memory Guard"
    WScript.Quit 1
End If

pyw = ""
Dim candidates
candidates = Array( _
    sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Python\pythoncore-3.15-64\pythonw.exe", _
    sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Python\pythoncore-3.14-64\pythonw.exe", _
    sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Python\pythoncore-3.13-64\pythonw.exe", _
    sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Python\pythoncore-3.12-64\pythonw.exe", _
    sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python\Python315\pythonw.exe", _
    sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python\Python313\pythonw.exe", _
    sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python\Python312\pythonw.exe", _
    sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Microsoft\WindowsApps\pyw.exe" )

For Each item In candidates
    If pyw = "" Then
        If fso.FileExists(item) Then pyw = item
    End If
Next

' fallback: scan LOCALAPPDATA\Programs\Python\*
If pyw = "" Then
    root = sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python"
    If fso.FolderExists(root) Then
        For Each sub_ In fso.GetFolder(root).SubFolders
            If pyw = "" Then
                If fso.FileExists(sub_.Path & "\pythonw.exe") Then
                    pyw = sub_.Path & "\pythonw.exe"
                End If
            End If
        Next
    End If
End If

If pyw = "" Then
    MsgBox "pythonw.exe not found. Please install Python 3 (with Tcl/Tk).", 16, "Memory Guard"
    WScript.Quit 1
End If

If LCase(Right(pyw, 8)) = "pyw.exe" Then
    cmd = """" & pyw & """ -3 """ & script & """"
Else
    cmd = """" & pyw & """ """ & script & """"
End If

sh.CurrentDirectory = base
sh.Run cmd, 1, False
