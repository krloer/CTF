Set utf8 = CreateObject("System.Text.UTF8Encoding")
Set b64Enc = CreateObject("System.Security.Cryptography.ToBase64Transform")
Set b64Dec = CreateObject("System.Security.Cryptography.FromBase64Transform")
Set mac = CreateObject("System.Security.Cryptography.HMACSHA256")
Set aes = CreateObject("System.Security.Cryptography.RijndaelManaged")
Set mem = CreateObject("System.IO.MemoryStream")
Set stream = CreateObject("ADODB.Stream")

Function Min(a, b)
    Min = a
    If b < a Then Min = b
End Function

Function B64Encode(bytes)
    blockSize = b64Enc.InputBlockSize
    For offset = 0 To LenB(bytes) - 1 Step blockSize
        length = Min(blockSize, LenB(bytes) - offset)
        b64Block = b64Enc.TransformFinalBlock((bytes), offset, length)
        result = result & utf8.GetString((b64Block))
    Next
    B64Encode = result
End Function

Function B64Decode(b64Str)
    bytes = utf8.GetBytes_4(b64Str)
    B64Decode = b64Dec.TransformFinalBlock((bytes), 0, LenB(bytes))
End Function

Function ConcatBytes(a, b)
    mem.SetLength(0)
    mem.Write (a), 0, LenB(a)
    mem.Write (b), 0, LenB(b)
    ConcatBytes = mem.ToArray()
End Function

Function ComputeMAC(msgBytes, keyBytes)
    mac.Key = keyBytes
    ComputeMAC = mac.ComputeHash_2((msgBytes))
End Function

Function Encrypt(plaintext, aesKey, macKey)
    aes.GenerateIV()
    aesKeyBytes = B64Decode(aesKey)
    macKeyBytes = B64Decode(macKey)
    Set aesEnc = aes.CreateEncryptor_2((aesKeyBytes), aes.IV)
    plainBytes = utf8.GetBytes_4(plaintext)
    cipherBytes = aesEnc.TransformFinalBlock((plainBytes), 0, LenB(plainBytes))
    macBytes = ComputeMAC(ConcatBytes(aes.IV, cipherBytes), macKeyBytes)
    Encrypt = B64Encode(macBytes) & ":" & B64Encode(aes.IV) & ":" & B64Encode(cipherBytes)
End Function

Function FileToBytes(p)
    With stream
        .Open
        .Type = 1
        .LoadFromFile p
        FileToBytes = .Read()
        .Close
    End With
End Function

Function BytesToFile(b, p)
    With stream
        .Open
        .Type = 1
        .Write b
        .SaveToFile p, 2
        .Close
    End With
End Function

Function BytesToStr(b, p)
    With stream
      .Open
      .Type = 1
      .Write b
      .Position = 0
      .Type = 2
      .Charset = "ascii"
      .Position = p
      BytesToStr = .ReadText()
      .Close
    End With
End Function

Function TrimBytes(b, p, t)
    With stream
      .Open
      .Type = 1
      .Write b
      .Position = p
      TrimBytes = .Read(t)
      .Close
    End With
End Function