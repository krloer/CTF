.intel_syntax noprefix
.globl _start
.section .text

_start:

    xor rdx, rdx
    mov rsi, 0x1
    mov rdi, 0x2
    mov rax, 0x29
    syscall

    mov [socketFD], rax

    mov rdx, 0x10
    lea rsi, [sockaddr]
    movzx rdi, byte ptr [socketFD]
    mov rax, 0x31
    syscall

    test rax, rax
    jnz exit

    xor rsi, rsi
    movzx rdi, byte ptr [socketFD]
    mov rax, 0x32
    syscall

serve:

    xor rdx, rdx
    xor rsi, rsi
    movzx rdi, byte ptr [socketFD]
    mov rax, 0x2b
    syscall

    mov [clientFD], al

    mov rax, 0x39
    syscall

    cmp rax, 0x0
    je readRequest

    movzx rdi, byte ptr [clientFD]
    mov rax, 0x3
    syscall

    jmp serve

readRequest:

    movzx rdi, byte ptr [socketFD]
    mov rax, 0x3
    syscall

    mov rdx, 0xffff
    lea rsi, [requestBuffer]
    movzx rdi, byte ptr [clientFD]
    xor rax, rax
    syscall

    mov rcx, -0x1
    lea rdx, [methodsLookupTable - 0x18]

    readRequest.Search:

        add rdx, 0x18
        mov rdi, [rdx]
        lea rsi, [requestBuffer]

        repz cmpsb
        movzx rax, byte ptr [stringTerminators + 0x1]
        cmp byte ptr [rsi - 0x1], al
        jnz readRequest.Search

    mov rax, [rdx + 0x10]
    jmp rax

getHandler:

    call getPath

    xor rdx, rdx
    xor rsi, rsi
    lea rdi, [pathBuffer]
    mov rax, 0x2
    syscall

    cmp rax, -0x1
    jle fileNotFound
    mov [fileFD], al

    xor rdi, rdi
    call printResponseCode
    call printNewline

    mov r10, 0xffff
    xor rdx, rdx
    movzx rsi, byte ptr [fileFD]
    movzx rdi, byte ptr [clientFD]
    mov rax, 0x28
    syscall

    movzx rdi, byte ptr [fileFD]
    mov rax, 0x3
    syscall

    xor rdi, rdi
    jmp exit

headHandler:

    call getPath

    xor rdx, rdx
    xor rsi, rsi
    lea rdi, [pathBuffer]
    mov rax, 0x2
    syscall

    cmp rax, -0x1
    jle fileNotFound
    mov [fileFD], al

    xor rdi, rdi
    call printResponseCode

    movzx rdi, byte ptr [fileFD]
    mov rax, 0x3
    syscall

    jmp exit

postHandler:

    xor rdx, rdx
    mov rsi, 0x1
    lea rdi, [devNull]
    mov rax, 0x2
    syscall

    cmp rax, -0x1
    jle methodNotAllowed
    mov [fileFD], al

    movzx rsi, byte ptr [stringTerminators]
    lea rdi, [requestBuffer]
    push rdi

    call getStringLength

    mov rdx, rcx
    pop rsi
    movzx rdi, byte ptr [fileFD]
    mov rax, 0x1
    syscall

    movzx rdi, byte ptr [fileFD]
    mov rax, 0x3
    syscall

    xor rdi, rdi
    call printResponseCode

    xor rdx, rdx
    jmp exit

putHandler:

    call auth
    cmp rax, -0x1
    jz methodNotAllowed
    
    call getPath

    mov rdx, 0755
    mov rsi, 0x40 | 0x1
    lea rdi, [pathBuffer]
    mov rax, 0x2
    syscall

    cmp rax, -0x1
    jle methodNotAllowed
    mov [fileFD], al

    call getBody

    mov rdx, rcx
    lea rsi, [fileBuffer]
    movzx rdi, byte ptr [fileFD]
    mov rax, 0x1
    syscall

    movzx rdi, byte ptr [fileFD]
    mov rax, 0x3
    syscall

    xor rdi, rdi
    call printResponseCode

    mov rdi, 0x1
    jmp exit

deleteHandler:

    call auth
    cmp rax, -0x1
    jz methodNotAllowed

    call getPath

    lea rdi, [pathBuffer]
    mov rax, 0x57
    syscall

    xor rdi, rdi
    mov rsi, 0x1
    mov rdx, 0x2
    cmp rax, -0x2
    cmove rdi, rsi
    cmp rax, -0xd
    cmove rdi, rdx
    call printResponseCode

    jmp exit

connectHandler:

    mov rdi, 0x4
    call printResponseCode

    mov rdi, -0x1
    jmp exit

optionsHandler:

    xor rdi, rdi
    call printResponseCode

    mov rdx, offset allow.length
    lea rsi, [allow]
    call socketWrite

    mov rcx, offset numberOfMethods
    lea rbx, [methodsLookupTable]

    optionsHandler.Loop:

        push rcx
        push rcx
        lea rax, [rbx + 0x8]
        movzx rdx, byte ptr [rax]
        mov rsi, [rbx]
        call socketWrite

        pop rcx
        dec rcx
        jz optionsHandler.Skip

        call printCommaSpace

        optionsHandler.Skip:

        add rbx, 0x18
        pop rcx
        dec rcx
        test rcx, rcx
        jnz optionsHandler.Loop

    call printNewline

    mov rdi, 0x1
    jmp exit

flagHandler:

    .include "flag.s"

traceHandler:

    xor rdi, rdi
    call printResponseCode
    call printNewline

    movzx rsi, byte ptr [stringTerminators]
    lea rdi, [requestBuffer]
    push rdi

    call getStringLength

    mov rdx, rcx
    pop rsi
    call socketWrite

    xor rdi, rdi
    jmp exit

patchHandler:

    mov rdi, 0x4
    call printResponseCode

    mov rdi, -0x1
    jmp exit

getPath:

    mov rcx, offset basePath.length
    lea rsi, [rip + basePath]
    lea rdi, [pathBuffer]
    rep movsb
    push rdi

    mov rcx, -0x1
    movzx rax, byte ptr [stringTerminators + 0x1]
    lea rdi, [requestBuffer]
    repnz scasb
    push rdi

    movzx rsi, byte ptr [stringTerminators + 0x1]
    call getStringLength

    pop rsi
    pop rdi
    rep movsb

    ret

getBody:

    mov dx, word ptr [newline]
    shl edx, 16
    mov dx, word ptr [newline]
    lea rdi, [requestBuffer - 0x1]

    getBody.Loop:

        inc rdi
        cmp edx, dword ptr [rdi]
        jne getBody.Loop

    add rdi, 0x4
    movzx rsi, byte ptr [stringTerminators]
    push rdi

    call getStringLength

    pop rsi
    push rcx
    lea rdi, [fileBuffer]
    rep movsb

    pop rcx

    ret

getStringLength:

    mov rcx, -0x1
    movzx rax, sil
    repnz scasb
    inc rcx
    not rcx

    ret

socketWrite:

    movzx rdi, byte ptr [clientFD]
    mov rax, 0x1
    syscall

    ret

printNewline:

    mov rdx, offset newline.length
    lea rsi, [newline]
    call socketWrite

    ret

printCommaSpace:

    mov rdx, offset commaSpace.length
    lea rsi, [commaSpace]
    call socketWrite

    ret

printResponseCode:

    shl rdi, 0x1
    mov rdx, [responseCodeLookupTable + rdi * 0x8 + 0x8]
    mov rsi, [responseCodeLookupTable + rdi * 0x8]

    call socketWrite
    call printNewline

    ret

fileNotFound:

    mov rdi, 0x1
    call printResponseCode

    mov rdi, -0x1
    jmp exit

methodNotAllowed:

    mov rdi, 0x2
    call printResponseCode

    mov rdi, -0x1
    jmp exit

getHeaderValue:

    mov r12, rdi  

    lea rdi, [requestBuffer]
    call getNumberOfHeaders

    mov r13, rcx
    lea rbx, [headerLookupTable]

    mov rcx, -0x1
    mov rax, r12
    shl rax, 3
    add rbx, rax
    mov rsi, [rbx]
    lea rdi, [requestBuffer]

    inc r13
    jmp getHeaderValue.Next

    getHeaderValue.Compare:

        mov rsi, [rbx]
        repz cmpsb

        cmp byte ptr [rdi - 2], 0x3a
        jnz getHeaderValue.Next
        
        jmp getHeaderValue.Done

    getHeaderValue.Next:

        mov al, byte ptr [newline]
        repnz scasb
        jnz getHeaderValue.NotFound

        mov al, byte ptr [newline + 1]
        repnz scasb
        jnz getHeaderValue.NotFound

        dec r13
        jz getHeaderValue.NotFound

        jmp getHeaderValue.Compare

    getHeaderValue.NotFound:

        xor rdi, rdi

    getHeaderValue.Done:

        mov rax, rdi
        ret

getNumberOfHeaders:

    xor r10, r10
    mov rcx, -0x1
    mov rax, 0x0a

    getNumberOfHeaders.Search:

        repnz scasb
        jnz getNumberOfHeaders.Done

        cmp byte ptr [rdi - 2], 0x0d
        jnz getNumberOfHeaders.Search

        cmp word ptr [rdi], 0x0a0d
        jnz getNumberOfHeaders.Increment

        jmp getNumberOfHeaders.Done

    getNumberOfHeaders.Increment:

        inc r10
        jmp getNumberOfHeaders.Search

    getNumberOfHeaders.Done:

    mov rcx, r10
    ret

auth:

    mov rdi, 0x6
    call getHeaderValue
    mov rdi, rax

    .include "auth.s"

    ret

exit:

    mov rax, 0x3c
    syscall

.section .data

    .lcomm pathBuffer 0xff
    .lcomm fileBuffer 0xfffff
    .lcomm requestBuffer 0xffff
    .lcomm socketFD 0x1
    .lcomm clientFD 0x1
    .lcomm fileFD 0x1

    sockaddr: .octa 0x00000000000000000000000098e20002
    stringTerminators: .byte 0x0, 0x20, 0x0a
    devNull: .string "/dev/null"
    basePath: .string "/var/www/html"
    .equ basePath.length, . - basePath - 0x1
    newline: .string "\r\n"
    .equ newline.length, . - newline - 0x1
    commaSpace: .string ", "
    .equ commaSpace.length, . - commaSpace - 0x1

    responseCodes:
        HTTP_200: .string "HTTP/1.1 200 OK"
        .equ HTTP_200.length, . - HTTP_200 - 0x1
        HTTP_404: .string "HTTP/1.1 404 Not Found"
        .equ HTTP_404.length, . - HTTP_404 - 0x1
        HTTP_405: .string "HTTP/1.1 405 Method not allowed"
        .equ HTTP_405.length, . - HTTP_405 - 0x1
        HTTP_500: .string "HTTP/1.1 500 Internal Server Error"
        .equ HTTP_500.length, . - HTTP_500 - 0x1
        HTTP_501: .string "HTTP/1.1 501 Not Implemented"
        .equ HTTP_501.length, . - HTTP_501 - 0x1

    methods:
        GET: .string "GET"
        .equ GET.length, . - GET - 0x1
        HEAD: .string "HEAD"
        .equ HEAD.length, . - HEAD - 0x1
        POST: .string "POST"
        .equ POST.length, . - POST - 0x1
        PUT: .string "PUT"
        .equ PUT.length, . - PUT - 0x1
        DELETE: .string "DELETE"
        .equ DELETE.length, . - DELETE - 0x1
        CONNECT: .string "CONNECT"
        .equ CONNECT.length, . - CONNECT - 0x1
        OPTIONS: .string "OPTIONS"
        .equ OPTIONS.length, . - OPTIONS - 0x1
        FLAG: .string "FLAG"
        .equ FLAG.length, . - FLAG - 0x1
        TRACE: .string "TRACE"
        .equ TRACE.length, . - TRACE - 0x1
        PATCH: .string "PATCH"
        .equ PATCH.length, . - PATCH - 0x1

    headers:
        userAgent: .string "User-Agent:"
        contentType: .string "Content-Type:"
        contentEncoding: .string "Content-Encoding:"
        contentLength: .string "Content-Length:"
        acceptLanguage: .string "Accept-Language:"
        authorization: .string "Authorization:"
        keepAlive: .string "Keep-Alive:"
        host: .string "Host:"
        cookie: .string "Cookie:"
        referer: .string "Referer:"
        xForwardedFor: .string "X-Forwarded-For:"
        allow: .string "Allow: "
        .equ allow.length, . - allow - 0x1

    headerLookupTable:
        .quad allow
        .quad userAgent
        .quad contentType
        .quad contentEncoding
        .quad contentLength
        .quad acceptLanguage
        .quad authorization
        .quad keepAlive
        .quad host
        .quad cookie
        .quad referer
        .quad xForwardedFor

    responseCodeLookupTable:
        .quad HTTP_200,  HTTP_200.length
        .quad HTTP_404,  HTTP_404.length
        .quad HTTP_405,  HTTP_405.length
        .quad HTTP_500,  HTTP_500.length
        .quad HTTP_501,  HTTP_501.length

    methodsLookupTable:
        .quad GET,      GET.length,      getHandler
        .quad HEAD,     HEAD.length,     headHandler
        .quad POST,     POST.length,     postHandler
        .quad PUT,      PUT.length,      putHandler
        .quad DELETE,   DELETE.length,   deleteHandler
        .quad CONNECT,  CONNECT.length,  connectHandler
        .quad OPTIONS,  OPTIONS.length,  optionsHandler
        .quad FLAG,     FLAG.length,     flagHandler
        .quad TRACE,    TRACE.length,    traceHandler
        .quad PATCH,    PATCH.length,    patchHandler
        .equ numberOfMethods, (. - methodsLookupTable) / (0x8 * 0x3)

// as -o webserver.o webserver.s && ld -o webserver webserver.o && ./webserver
