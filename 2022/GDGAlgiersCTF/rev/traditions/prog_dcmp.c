undefined8 main(void)

{
  int iVar1;
  size_t sVar2;
  ulong uVar3;
  char input [48];
  uint local_e8 [4];
  undefined4 local_d8;
  undefined4 local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  uint local_24;
  uint local_20;
  int i;
  
  local_e8[0] = 0x15; 
  local_e8[1] = 0x91;
  local_e8[2] = 0x2a;
  local_e8[3] = 0x59;
  local_d8 = 0x72; //confused decompile, these are array values in order
  local_d4 = 0x1e;
  local_d0 = 0xd9;
  local_cc = 10;
  local_c8 = 0xb6;
  local_c4 = 0xf1;
  local_c0 = 0x2a;
  local_bc = 0xba;
  local_b8 = 0x5f;
  local_b4 = 0x66;
  local_b0 = 0x70;
  local_ac = 0x61;
  local_a8 = 0x4f;
  local_a4 = 0xf7;
  local_a0 = 0xd1;
  local_9c = 0x49;
  local_98 = 0xd6;
  local_94 = 0xac;
  local_90 = 0xb4;
  local_8c = 0x21;
  local_88 = 0xb2;
  local_84 = 0x1e;
  local_80 = 0x94;
  local_7c = 0x28;
  local_78 = 0x5a;
  local_74 = 0x57;
  local_70 = 0xaa;
  local_6c = 0x15;
  local_68 = 199;
  local_64 = 10;
  local_60 = 200;
  local_5c = 0xa3;
  local_58 = 0xf0;
  local_54 = 0x76;
  local_50 = 3;
  local_4c = 0x34;
  local_48 = 0x88;
  local_44 = 0xe1;
  local_40 = 0x24;
  local_3c = 99;
  local_38 = 0xc2;
  local_34 = 0x13;
  local_30 = 0x5a;
  local_2c = 2;
  srand(0x7e6);
  printf("Enter the password : ");
  fgets(input,0x30,stdin); //read 47 bytes(+ \0) into input
  sVar2 = strlen(input); 
  if (sVar2 != 0x2f) { //input length = 47
    printf("Wrong length");
    exit(1);
  }
  i = 0;
  while( true ) {
    uVar3 = (ulong)i;
    sVar2 = strlen(input); //47
    if (sVar2 <= uVar3) { //if 47 chars passed
      puts("Correct, you can submit the flag");
      return 0;
    }
    iVar1 = rand(); // rand value (first time: 1341262422)
    local_20 = (uint)(iVar1 >> 0x1f) >> 0x18; // always 0
    local_20 = (iVar1 + local_20 & 0xff) - local_20; // rand value (+ 0) & 255 (first time: 01010110 (86))
    local_24 = (int)input[i] ^ local_20; // ascii val of input[i] ^ local_20
    if (local_24 != local_e8[i]) break; //21, 145, 42, 89 ...
    i = i + 1;
  }
  printf("WRONG");
  exit(1);
}