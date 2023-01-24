0x0000555555558040 <+0>:     cmp    eax,0xe5894855
   0x0000555555558045 <+5>:     mov    QWORD PTR [rbp-0x18],rdi 
   0x0000555555558049 <+9>:     mov    DWORD PTR [rbp-0x4],0x0 ; we want rbp-0x4 to remain as 0
   0x0000555555558050 <+16>:    mov    rax,QWORD PTR [rbp-0x18] ; 
   0x0000555555558054 <+20>:    add    rax,0x15
   0x0000555555558058 <+24>:    movzx  edx,BYTE PTR [rax]
   0x000055555555805b <+27>:    mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555805f <+31>:    add    rax,0x18
   0x0000555555558063 <+35>:    movzx  eax,BYTE PTR [rax]
   0x0000555555558066 <+38>:    xor    eax,edx
   0x0000555555558068 <+40>:    cmp    al,0x6c                                ; input[0x15]^input[0x18] = 0x6c
   0x000055555555806a <+42>:    je     0x555555558073 <checker+51>
   0x000055555555806c <+44>:    mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558073 <+51>:    mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558077 <+55>:    add    rax,0x23
   0x000055555555807b <+59>:    movzx  edx,BYTE PTR [rax]
   0x000055555555807e <+62>:    mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558082 <+66>:    add    rax,0x26
   0x0000555555558086 <+70>:    movzx  eax,BYTE PTR [rax]
   0x0000555555558089 <+73>:    xor    eax,edx
   0x000055555555808b <+75>:    cmp    al,0xa                                 ; input[0x23]^input[0x26] = 0xa
   0x000055555555808d <+77>:    je     0x555555558096 <checker+86>
   0x000055555555808f <+79>:    mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558096 <+86>:    mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555809a <+90>:    add    rax,0xa
   0x000055555555809e <+94>:    movzx  edx,BYTE PTR [rax]
   0x00005555555580a1 <+97>:    mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555580a5 <+101>:   add    rax,0xd
   0x00005555555580a9 <+105>:   movzx  eax,BYTE PTR [rax]
   0x00005555555580ac <+108>:   xor    eax,edx
   0x00005555555580ae <+110>:   cmp    al,0xa                                  ; input[0xa]^input[0xd] = 0xa
   0x00005555555580b0 <+112>:   je     0x5555555580b9 <checker+121>
   0x00005555555580b2 <+114>:   mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555580b9 <+121>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555580bd <+125>:   movzx  eax,BYTE PTR [rax]                      ; input[0] = 0x55
   0x00005555555580c0 <+128>:   cmp    al,0x55
   0x00005555555580c2 <+130>:   je     0x5555555580cb <checker+139>
   0x00005555555580c4 <+132>:   mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555580cb <+139>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555580cf <+143>:   add    rax,0x19
   0x00005555555580d3 <+147>:   movzx  edx,BYTE PTR [rax]
   0x00005555555580d6 <+150>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555580da <+154>:   add    rax,0x1c
   0x00005555555580de <+158>:   movzx  eax,BYTE PTR [rax]
   0x00005555555580e1 <+161>:   xor    eax,edx
   0x00005555555580e3 <+163>:   cmp    al,0x5c                                  ; input[0x19]^input[0x1c] = 0x5c
   0x00005555555580e5 <+165>:   je     0x5555555580ee <checker+174>
   0x00005555555580e7 <+167>:   mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555580ee <+174>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555580f2 <+178>:   add    rax,0x6
   0x00005555555580f6 <+182>:   movzx  edx,BYTE PTR [rax]
   0x00005555555580f9 <+185>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555580fd <+189>:   add    rax,0x9
   0x0000555555558101 <+193>:   movzx  eax,BYTE PTR [rax]
   0x0000555555558104 <+196>:   xor    eax,edx
   0x0000555555558106 <+198>:   cmp    al,0x6b                                  ; input[0x6]^input[0x9] = 0x6b
   0x0000555555558108 <+200>:   je     0x555555558111 <checker+209>
   0x000055555555810a <+202>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558111 <+209>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558115 <+213>:   add    rax,0xc
   0x0000555555558119 <+217>:   movzx  edx,BYTE PTR [rax]
   0x000055555555811c <+220>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558120 <+224>:   add    rax,0xf
   0x0000555555558124 <+228>:   movzx  eax,BYTE PTR [rax]
   0x0000555555558127 <+231>:   xor    eax,edx
   0x0000555555558129 <+233>:   cmp    al,0x41
   0x000055555555812b <+235>:   je     0x555555558134 <checker+244>
   0x000055555555812d <+237>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558134 <+244>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558138 <+248>:   add    rax,0x27
   0x000055555555813c <+252>:   movzx  edx,BYTE PTR [rax]
   0x000055555555813f <+255>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558143 <+259>:   add    rax,0x2a
   0x0000555555558147 <+263>:   movzx  eax,BYTE PTR [rax]
   0x000055555555814a <+266>:   xor    eax,edx
   0x000055555555814c <+268>:   cmp    al,0x54
   0x000055555555814e <+270>:   je     0x555555558157 <checker+279>
   0x0000555555558150 <+272>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558157 <+279>:   mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555815b <+283>:   add    rax,0x2f
   0x000055555555815f <+287>:   movzx  edx,BYTE PTR [rax]
   0x0000555555558162 <+290>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558166 <+294>:   add    rax,0x2
   0x000055555555816a <+298>:   movzx  eax,BYTE PTR [rax]
   0x000055555555816d <+301>:   xor    eax,edx
   0x000055555555816f <+303>:   cmp    al,0x3e
   0x0000555555558171 <+305>:   je     0x55555555817a <checker+314>
   0x0000555555558173 <+307>:   mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555817a <+314>:   mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555817e <+318>:   add    rax,0x2e
   0x0000555555558182 <+322>:   movzx  edx,BYTE PTR [rax]
   0x0000555555558185 <+325>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558189 <+329>:   add    rax,0x1
   0x000055555555818d <+333>:   movzx  eax,BYTE PTR [rax]
   0x0000555555558190 <+336>:   xor    eax,edx
   0x0000555555558192 <+338>:   cmp    al,0x23
   0x0000555555558194 <+340>:   je     0x55555555819d <checker+349>
   0x0000555555558196 <+342>:   mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555819d <+349>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555581a1 <+353>:   add    rax,0x9
   0x00005555555581a5 <+357>:   movzx  edx,BYTE PTR [rax]
   0x00005555555581a8 <+360>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555581ac <+364>:   add    rax,0xc
   0x00005555555581b0 <+368>:   movzx  eax,BYTE PTR [rax]
   0x00005555555581b3 <+371>:   cmp    dl,al                                        ; input[0x9] = input[0xc]
   0x00005555555581b5 <+373>:   je     0x5555555581be <checker+382>
   0x00005555555581b7 <+375>:   mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555581be <+382>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555581c2 <+386>:   add    rax,0x24
   0x00005555555581c6 <+390>:   movzx  edx,BYTE PTR [rax]
   0x00005555555581c9 <+393>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555581cd <+397>:   add    rax,0x27
   0x00005555555581d1 <+401>:   movzx  eax,BYTE PTR [rax]
   0x00005555555581d4 <+404>:   xor    eax,edx
   0x00005555555581d6 <+406>:   cmp    al,0x47
   0x00005555555581d8 <+408>:   je     0x5555555581e1 <checker+417>
   0x00005555555581da <+410>:   mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555581e1 <+417>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555581e5 <+421>:   add    rax,0xf
   0x00005555555581e9 <+425>:   movzx  edx,BYTE PTR [rax]
   0x00005555555581ec <+428>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555581f0 <+432>:   add    rax,0x12
   0x00005555555581f4 <+436>:   movzx  eax,BYTE PTR [rax]
   0x00005555555581f7 <+439>:   xor    eax,edx
   0x00005555555581f9 <+441>:   cmp    al,0x6
   0x00005555555581fb <+443>:   je     0x555555558204 <checker+452>
   0x00005555555581fd <+445>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558204 <+452>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558208 <+456>:   add    rax,0xd
   0x000055555555820c <+460>:   movzx  edx,BYTE PTR [rax]
   0x000055555555820f <+463>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558213 <+467>:   add    rax,0x10
   0x0000555555558217 <+471>:   movzx  eax,BYTE PTR [rax]
   0x000055555555821a <+474>:   xor    eax,edx
   0x000055555555821c <+476>:   cmp    al,0x37
   0x000055555555821e <+478>:   je     0x555555558227 <checker+487>
   0x0000555555558220 <+480>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558227 <+487>:   mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555822b <+491>:   add    rax,0x14
   0x000055555555822f <+495>:   movzx  edx,BYTE PTR [rax]
   0x0000555555558232 <+498>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558236 <+502>:   add    rax,0x17
   0x000055555555823a <+506>:   movzx  eax,BYTE PTR [rax]
   0x000055555555823d <+509>:   xor    eax,edx
   0x000055555555823f <+511>:   cmp    al,0xc
   0x0000555555558241 <+513>:   je     0x55555555824a <checker+522>
   0x0000555555558243 <+515>:   mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555824a <+522>:   mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555824e <+526>:   add    rax,0x5
   0x0000555555558252 <+530>:   movzx  eax,BYTE PTR [rax]
   0x0000555555558255 <+533>:   cmp    al,0x7b
   0x0000555555558257 <+535>:   je     0x555555558260 <checker+544>
   0x0000555555558259 <+537>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558260 <+544>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558264 <+548>:   add    rax,0x16
   0x0000555555558268 <+552>:   movzx  edx,BYTE PTR [rax]
   0x000055555555826b <+555>:   mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555826f <+559>:   add    rax,0x19
   0x0000555555558273 <+563>:   movzx  eax,BYTE PTR [rax]
   0x0000555555558276 <+566>:   xor    eax,edx
   0x0000555555558278 <+568>:   cmp    al,0x59
   0x000055555555827a <+570>:   je     0x555555558283 <checker+579>
   0x000055555555827c <+572>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558283 <+579>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558287 <+583>:   add    rax,0x13
   0x000055555555828b <+587>:   movzx  edx,BYTE PTR [rax]
   0x000055555555828e <+590>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558292 <+594>:   add    rax,0x16
   0x0000555555558296 <+598>:   movzx  eax,BYTE PTR [rax]
   0x0000555555558299 <+601>:   xor    eax,edx
   0x000055555555829b <+603>:   cmp    al,0x6
   0x000055555555829d <+605>:   je     0x5555555582a6 <checker+614>
   0x000055555555829f <+607>:   mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555582a6 <+614>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555582aa <+618>:   add    rax,0x20
   0x00005555555582ae <+622>:   movzx  edx,BYTE PTR [rax]
   0x00005555555582b1 <+625>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555582b5 <+629>:   add    rax,0x23
   0x00005555555582b9 <+633>:   movzx  eax,BYTE PTR [rax]
   0x00005555555582bc <+636>:   xor    eax,edx
   0x00005555555582be <+638>:   cmp    al,0x48
   0x00005555555582c0 <+640>:   je     0x5555555582c9 <checker+649>
   0x00005555555582c2 <+642>:   mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555582c9 <+649>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555582cd <+653>:   add    rax,0x2d
   0x00005555555582d1 <+657>:   movzx  edx,BYTE PTR [rax]
   0x00005555555582d4 <+660>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555582d8 <+664>:   movzx  eax,BYTE PTR [rax]
   0x00005555555582db <+667>:   xor    eax,edx
   0x00005555555582dd <+669>:   cmp    al,0x3b
   0x00005555555582df <+671>:   je     0x5555555582e8 <checker+680>
   0x00005555555582e1 <+673>:   mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555582e8 <+680>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555582ec <+684>:   add    rax,0x1d
   0x00005555555582f0 <+688>:   movzx  edx,BYTE PTR [rax]
   0x00005555555582f3 <+691>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555582f7 <+695>:   add    rax,0x20
   0x00005555555582fb <+699>:   movzx  eax,BYTE PTR [rax]
   0x00005555555582fe <+702>:   xor    eax,edx
   0x0000555555558300 <+704>:   cmp    al,0x42
   0x0000555555558302 <+706>:   je     0x55555555830b <checker+715>
   0x0000555555558304 <+708>:   mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555830b <+715>:   mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555830f <+719>:   add    rax,0x2c
   0x0000555555558313 <+723>:   movzx  edx,BYTE PTR [rax]
   0x0000555555558316 <+726>:   mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555831a <+730>:   add    rax,0x2f
   0x000055555555831e <+734>:   movzx  eax,BYTE PTR [rax]
   0x0000555555558321 <+737>:   xor    eax,edx
   0x0000555555558323 <+739>:   cmp    al,0x4c
   0x0000555555558325 <+741>:   je     0x55555555832e <checker+750>
   0x0000555555558327 <+743>:   mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555832e <+750>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558332 <+754>:   add    rax,0x1e
   0x0000555555558336 <+758>:   movzx  edx,BYTE PTR [rax]
   0x0000555555558339 <+761>:   mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555833d <+765>:   add    rax,0x21
   0x0000555555558341 <+769>:   movzx  eax,BYTE PTR [rax]
   0x0000555555558344 <+772>:   xor    eax,edx
   0x0000555555558346 <+774>:   cmp    al,0x6c
   0x0000555555558348 <+776>:   je     0x555555558351 <checker+785>
   0x000055555555834a <+778>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558351 <+785>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558355 <+789>:   add    rax,0x5
   0x0000555555558359 <+793>:   movzx  edx,BYTE PTR [rax]
   0x000055555555835c <+796>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558360 <+800>:   add    rax,0x8
   0x0000555555558364 <+804>:   movzx  eax,BYTE PTR [rax]
   0x0000555555558367 <+807>:   xor    eax,edx
   0x0000555555558369 <+809>:   cmp    al,0x29
   0x000055555555836b <+811>:   je     0x555555558374 <checker+820>
   0x000055555555836d <+813>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558374 <+820>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558378 <+824>:   add    rax,0x1b
   0x000055555555837c <+828>:   movzx  edx,BYTE PTR [rax]
   0x000055555555837f <+831>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558383 <+835>:   add    rax,0x1e
   0x0000555555558387 <+839>:   movzx  eax,BYTE PTR [rax]
   0x000055555555838a <+842>:   xor    eax,edx
   0x000055555555838c <+844>:   cmp    al,0x70
   0x000055555555838e <+846>:   je     0x555555558397 <checker+855>
   0x0000555555558390 <+848>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558397 <+855>:   mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555839b <+859>:   add    rax,0x1a
   0x000055555555839f <+863>:   movzx  edx,BYTE PTR [rax]
   0x00005555555583a2 <+866>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555583a6 <+870>:   add    rax,0x1d
   0x00005555555583aa <+874>:   movzx  eax,BYTE PTR [rax]
   0x00005555555583ad <+877>:   xor    eax,edx
   0x00005555555583af <+879>:   cmp    al,0x55
   0x00005555555583b1 <+881>:   je     0x5555555583ba <checker+890>
   0x00005555555583b3 <+883>:   mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555583ba <+890>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555583be <+894>:   add    rax,0x1c
   0x00005555555583c2 <+898>:   movzx  edx,BYTE PTR [rax]
   0x00005555555583c5 <+901>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555583c9 <+905>:   add    rax,0x1f
   0x00005555555583cd <+909>:   movzx  eax,BYTE PTR [rax]
   0x00005555555583d0 <+912>:   xor    eax,edx
   0x00005555555583d2 <+914>:   cmp    al,0x6f
   0x00005555555583d4 <+916>:   je     0x5555555583dd <checker+925>
   0x00005555555583d6 <+918>:   mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555583dd <+925>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555583e1 <+929>:   add    rax,0x10
   0x00005555555583e5 <+933>:   movzx  edx,BYTE PTR [rax]
   0x00005555555583e8 <+936>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555583ec <+940>:   add    rax,0x13
   0x00005555555583f0 <+944>:   movzx  eax,BYTE PTR [rax]
   0x00005555555583f3 <+947>:   xor    eax,edx
   0x00005555555583f5 <+949>:   cmp    al,0x6a
   0x00005555555583f7 <+951>:   je     0x555555558400 <checker+960>
   0x00005555555583f9 <+953>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558400 <+960>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558404 <+964>:   add    rax,0x29
   0x0000555555558408 <+968>:   movzx  edx,BYTE PTR [rax]
   0x000055555555840b <+971>:   mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555840f <+975>:   add    rax,0x2c
   0x0000555555558413 <+979>:   movzx  eax,BYTE PTR [rax]
   0x0000555555558416 <+982>:   xor    eax,edx
   0x0000555555558418 <+984>:   cmp    al,0x44
   0x000055555555841a <+986>:   je     0x555555558423 <checker+995>
   0x000055555555841c <+988>:   mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558423 <+995>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558427 <+999>:   add    rax,0x25
   0x000055555555842b <+1003>:  movzx  edx,BYTE PTR [rax]
   0x000055555555842e <+1006>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558432 <+1010>:  add    rax,0x28
   0x0000555555558436 <+1014>:  movzx  eax,BYTE PTR [rax]
   0x0000555555558439 <+1017>:  xor    eax,edx
   0x000055555555843b <+1019>:  cmp    al,0x53
   0x000055555555843d <+1021>:  je     0x555555558446 <checker+1030>
   0x000055555555843f <+1023>:  mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558446 <+1030>:  mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555844a <+1034>:  add    rax,0x22
   0x000055555555844e <+1038>:  movzx  edx,BYTE PTR [rax]
   0x0000555555558451 <+1041>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558455 <+1045>:  add    rax,0x25
   0x0000555555558459 <+1049>:  movzx  eax,BYTE PTR [rax]
   0x000055555555845c <+1052>:  xor    eax,edx
   0x000055555555845e <+1054>:  cmp    al,0x5
   0x0000555555558460 <+1056>:  je     0x555555558469 <checker+1065>
   0x0000555555558462 <+1058>:  mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558469 <+1065>:  mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555846d <+1069>:  add    rax,0x26
   0x0000555555558471 <+1073>:  movzx  edx,BYTE PTR [rax]
   0x0000555555558474 <+1076>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558478 <+1080>:  add    rax,0x29
   0x000055555555847c <+1084>:  movzx  eax,BYTE PTR [rax]
   0x000055555555847f <+1087>:  xor    eax,edx
   0x0000555555558481 <+1089>:  cmp    al,0x11
   0x0000555555558483 <+1091>:  je     0x55555555848c <checker+1100>
   0x0000555555558485 <+1093>:  mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555848c <+1100>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558490 <+1104>:  add    rax,0x2
   0x0000555555558494 <+1108>:  movzx  edx,BYTE PTR [rax]
   0x0000555555558497 <+1111>:  mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555849b <+1115>:  add    rax,0x5
   0x000055555555849f <+1119>:  movzx  eax,BYTE PTR [rax]
   0x00005555555584a2 <+1122>:  xor    eax,edx
   0x00005555555584a4 <+1124>:  cmp    al,0x38
   0x00005555555584a6 <+1126>:  je     0x5555555584af <checker+1135>
   0x00005555555584a8 <+1128>:  mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555584af <+1135>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555584b3 <+1139>:  add    rax,0x17
   0x00005555555584b7 <+1143>:  movzx  edx,BYTE PTR [rax]
   0x00005555555584ba <+1146>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555584be <+1150>:  add    rax,0x1a
   0x00005555555584c2 <+1154>:  movzx  eax,BYTE PTR [rax]
   0x00005555555584c5 <+1157>:  xor    eax,edx
   0x00005555555584c7 <+1159>:  cmp    al,0x59
   0x00005555555584c9 <+1161>:  je     0x5555555584d2 <checker+1170>
   0x00005555555584cb <+1163>:  mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555584d2 <+1170>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555584d6 <+1174>:  add    rax,0x18
   0x00005555555584da <+1178>:  movzx  edx,BYTE PTR [rax]
   0x00005555555584dd <+1181>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555584e1 <+1185>:  add    rax,0x1b
   0x00005555555584e5 <+1189>:  movzx  eax,BYTE PTR [rax]
   0x00005555555584e8 <+1192>:  xor    eax,edx
   0x00005555555584ea <+1194>:  cmp    al,0x70
   0x00005555555584ec <+1196>:  je     0x5555555584f5 <checker+1205>
   0x00005555555584ee <+1198>:  mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555584f5 <+1205>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555584f9 <+1209>:  add    rax,0x8
   0x00005555555584fd <+1213>:  movzx  edx,BYTE PTR [rax]
   0x0000555555558500 <+1216>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558504 <+1220>:  add    rax,0xb
   0x0000555555558508 <+1224>:  movzx  eax,BYTE PTR [rax]
   0x000055555555850b <+1227>:  xor    eax,edx
   0x000055555555850d <+1229>:  cmp    al,0xd
   0x000055555555850f <+1231>:  je     0x555555558518 <checker+1240>
   0x0000555555558511 <+1233>:  mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558518 <+1240>:  mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555851c <+1244>:  add    rax,0x21
   0x0000555555558520 <+1248>:  movzx  edx,BYTE PTR [rax]
   0x0000555555558523 <+1251>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558527 <+1255>:  add    rax,0x24
   0x000055555555852b <+1259>:  movzx  eax,BYTE PTR [rax]
   0x000055555555852e <+1262>:  xor    eax,edx
   0x0000555555558530 <+1264>:  cmp    al,0x2b
   0x0000555555558532 <+1266>:  je     0x55555555853b <checker+1275>
   0x0000555555558534 <+1268>:  mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555853b <+1275>:  mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555853f <+1279>:  add    rax,0x2b
   0x0000555555558543 <+1283>:  movzx  edx,BYTE PTR [rax]
   0x0000555555558546 <+1286>:  mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555854a <+1290>:  add    rax,0x2e
   0x000055555555854e <+1294>:  movzx  eax,BYTE PTR [rax]
   0x0000555555558551 <+1297>:  cmp    dl,al
   0x0000555555558553 <+1299>:  je     0x55555555855c <checker+1308>
   0x0000555555558555 <+1301>:  mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555855c <+1308>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558560 <+1312>:  add    rax,0x1
   0x0000555555558564 <+1316>:  movzx  eax,BYTE PTR [rax]
   0x0000555555558567 <+1319>:  cmp    al,0x44
   0x0000555555558569 <+1321>:  je     0x555555558572 <checker+1330>
   0x000055555555856b <+1323>:  mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558572 <+1330>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558576 <+1334>:  add    rax,0x1f
   0x000055555555857a <+1338>:  movzx  edx,BYTE PTR [rax]
   0x000055555555857d <+1341>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558581 <+1345>:  add    rax,0x22
   0x0000555555558585 <+1349>:  movzx  eax,BYTE PTR [rax]
   0x0000555555558588 <+1352>:  xor    eax,edx
   0x000055555555858a <+1354>:  cmp    al,0x6b
   0x000055555555858c <+1356>:  je     0x555555558595 <checker+1365>
   0x000055555555858e <+1358>:  mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558595 <+1365>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558599 <+1369>:  add    rax,0x28
   0x000055555555859d <+1373>:  movzx  edx,BYTE PTR [rax]
   0x00005555555585a0 <+1376>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555585a4 <+1380>:  add    rax,0x2b
   0x00005555555585a8 <+1384>:  movzx  eax,BYTE PTR [rax]
   0x00005555555585ab <+1387>:  xor    eax,edx
   0x00005555555585ad <+1389>:  cmp    al,0x5
   0x00005555555585af <+1391>:  je     0x5555555585b8 <checker+1400>
   0x00005555555585b1 <+1393>:  mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555585b8 <+1400>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555585bc <+1404>:  add    rax,0xe
   0x00005555555585c0 <+1408>:  movzx  edx,BYTE PTR [rax]
   0x00005555555585c3 <+1411>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555585c7 <+1415>:  add    rax,0x11
   0x00005555555585cb <+1419>:  movzx  eax,BYTE PTR [rax]
   0x00005555555585ce <+1422>:  xor    eax,edx
   0x00005555555585d0 <+1424>:  cmp    al,0x33
   0x00005555555585d2 <+1426>:  je     0x5555555585db <checker+1435>
   0x00005555555585d4 <+1428>:  mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555585db <+1435>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555585df <+1439>:  add    rax,0x7
   0x00005555555585e3 <+1443>:  movzx  edx,BYTE PTR [rax]
   0x00005555555585e6 <+1446>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555585ea <+1450>:  add    rax,0xa
   0x00005555555585ee <+1454>:  movzx  eax,BYTE PTR [rax]
   0x00005555555585f1 <+1457>:  xor    eax,edx
   0x00005555555585f3 <+1459>:  cmp    al,0x54
   0x00005555555585f5 <+1461>:  je     0x5555555585fe <checker+1470>
   0x00005555555585f7 <+1463>:  mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555585fe <+1470>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558602 <+1474>:  add    rax,0x4
   0x0000555555558606 <+1478>:  movzx  eax,BYTE PTR [rax]
   0x0000555555558609 <+1481>:  cmp    al,0x46
   0x000055555555860b <+1483>:  je     0x555555558614 <checker+1492>
   0x000055555555860d <+1485>:  mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558614 <+1492>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558618 <+1496>:  add    rax,0x11
   0x000055555555861c <+1500>:  movzx  edx,BYTE PTR [rax]
   0x000055555555861f <+1503>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558623 <+1507>:  add    rax,0x14
   0x0000555555558627 <+1511>:  movzx  eax,BYTE PTR [rax]
   0x000055555555862a <+1514>:  xor    eax,edx
   0x000055555555862c <+1516>:  cmp    al,0x14
   0x000055555555862e <+1518>:  je     0x555555558637 <checker+1527>
   0x0000555555558630 <+1520>:  mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558637 <+1527>:  mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555863b <+1531>:  add    rax,0x3
   0x000055555555863f <+1535>:  movzx  edx,BYTE PTR [rax]
   0x0000555555558642 <+1538>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558646 <+1542>:  add    rax,0x6
   0x000055555555864a <+1546>:  movzx  eax,BYTE PTR [rax]
   0x000055555555864d <+1549>:  xor    eax,edx
   0x000055555555864f <+1551>:  cmp    al,0xc
   0x0000555555558651 <+1553>:  je     0x55555555865a <checker+1562>
   0x0000555555558653 <+1555>:  mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555865a <+1562>:  mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555865e <+1566>:  add    rax,0x4
   0x0000555555558662 <+1570>:  movzx  edx,BYTE PTR [rax]
   0x0000555555558665 <+1573>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558669 <+1577>:  add    rax,0x7
   0x000055555555866d <+1581>:  movzx  eax,BYTE PTR [rax]
   0x0000555555558670 <+1584>:  xor    eax,edx
   0x0000555555558672 <+1586>:  cmp    al,0x76
   0x0000555555558674 <+1588>:  je     0x55555555867d <checker+1597>
   0x0000555555558676 <+1590>:  mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555867d <+1597>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558681 <+1601>:  add    rax,0x2a
   0x0000555555558685 <+1605>:  movzx  edx,BYTE PTR [rax]
   0x0000555555558688 <+1608>:  mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555868c <+1612>:  add    rax,0x2d
   0x0000555555558690 <+1616>:  movzx  eax,BYTE PTR [rax]
   0x0000555555558693 <+1619>:  xor    eax,edx
   0x0000555555558695 <+1621>:  cmp    al,0x9
   0x0000555555558697 <+1623>:  je     0x5555555586a0 <checker+1632>
   0x0000555555558699 <+1625>:  mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555586a0 <+1632>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555586a4 <+1636>:  movzx  edx,BYTE PTR [rax]
   0x00005555555586a7 <+1639>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555586ab <+1643>:  add    rax,0x3
   0x00005555555586af <+1647>:  movzx  eax,BYTE PTR [rax]
   0x00005555555586b2 <+1650>:  xor    eax,edx
   0x00005555555586b4 <+1652>:  cmp    al,0x1
   0x00005555555586b6 <+1654>:  je     0x5555555586bf <checker+1663>
   0x00005555555586b8 <+1656>:  mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555586bf <+1663>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555586c3 <+1667>:  add    rax,0xb
   0x00005555555586c7 <+1671>:  movzx  edx,BYTE PTR [rax]
   0x00005555555586ca <+1674>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555586ce <+1678>:  add    rax,0xe
   0x00005555555586d2 <+1682>:  movzx  eax,BYTE PTR [rax]
   0x00005555555586d5 <+1685>:  xor    eax,edx
   0x00005555555586d7 <+1687>:  cmp    al,0x1c
   0x00005555555586d9 <+1689>:  je     0x5555555586e2 <checker+1698>
   0x00005555555586db <+1691>:  mov    DWORD PTR [rbp-0x4],0x1
   0x00005555555586e2 <+1698>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555586e6 <+1702>:  add    rax,0x1
   0x00005555555586ea <+1706>:  movzx  edx,BYTE PTR [rax]
   0x00005555555586ed <+1709>:  mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555586f1 <+1713>:  add    rax,0x4
   0x00005555555586f5 <+1717>:  movzx  eax,BYTE PTR [rax]
   0x00005555555586f8 <+1720>:  xor    eax,edx
   0x00005555555586fa <+1722>:  cmp    al,0x2
   0x00005555555586fc <+1724>:  je     0x555555558705 <checker+1733>
   0x00005555555586fe <+1726>:  mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558705 <+1733>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558709 <+1737>:  add    rax,0x12
   0x000055555555870d <+1741>:  movzx  edx,BYTE PTR [rax]
   0x0000555555558710 <+1744>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558714 <+1748>:  add    rax,0x15
   0x0000555555558718 <+1752>:  movzx  eax,BYTE PTR [rax]
   0x000055555555871b <+1755>:  xor    eax,edx
   0x000055555555871d <+1757>:  cmp    al,0x2b
   0x000055555555871f <+1759>:  je     0x555555558728 <checker+1768>
   0x0000555555558721 <+1761>:  mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558728 <+1768>:  mov    rax,QWORD PTR [rbp-0x18]
   0x000055555555872c <+1772>:  add    rax,0x2
   0x0000555555558730 <+1776>:  movzx  eax,BYTE PTR [rax]
   0x0000555555558733 <+1779>:  cmp    al,0x43
   0x0000555555558735 <+1781>:  je     0x55555555873e <checker+1790>
   0x0000555555558737 <+1783>:  mov    DWORD PTR [rbp-0x4],0x1
   0x000055555555873e <+1790>:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555558742 <+1794>:  add    rax,0x3
   0x0000555555558746 <+1798>:  movzx  eax,BYTE PTR [rax]
   0x0000555555558749 <+1801>:  cmp    al,0x54
   0x000055555555874b <+1803>:  je     0x555555558754 <checker+1812>
   0x000055555555874d <+1805>:  mov    DWORD PTR [rbp-0x4],0x1
   0x0000555555558754 <+1812>:  mov    eax,DWORD PTR [rbp-0x4]
   0x0000555555558757 <+1815>:  pop    rbp
   0x0000555555558758 <+1816>:  ret    
   0x0000555555558759 <+1817>:  add    BYTE PTR [rax],al

