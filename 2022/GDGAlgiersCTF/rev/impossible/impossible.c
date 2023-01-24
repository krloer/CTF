undefined8 main(void)

{
  time_t tVar1;
  long in_FS_OFFSET;
  byte local_13d;
  int local_13c;
  int local_138;
  int local_134;
  int local_130;
  undefined4 local_12c;
  undefined4 local_128 [4];
  undefined4 local_118;
  undefined4 local_114;
  undefined4 local_110;
  undefined4 local_10c;
  undefined4 local_108;
  undefined4 local_104;
  undefined4 local_100;
  undefined4 local_fc;
  undefined4 local_f8;
  undefined4 local_f4;
  undefined4 local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
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
  char local_79;
  char local_78 [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  fwrite("Let me check your secret: ",1,0x1a,stdout);
  fgets(local_78,100,stdin);
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  local_138 = rand();
  local_134 = rand();
  local_130 = rand();
  if (((local_138 == local_134) && (local_134 == local_130)) &&
     (local_130 == local_78[0] * local_138)) {
    local_128[0] = 6;
    local_128[1] = 0x3c;
    local_128[2] = 0x27;
    local_128[3] = 0x20;
    local_118 = 0x37;
    local_114 = 0;
    local_110 = 0x37;
    local_10c = 0x30;
    local_108 = 0x21;
    local_104 = 0x2c;
    local_100 = 0x31;
    local_fc = 0x20;
    local_f8 = 0x36;
    local_f4 = 0x3e;
    local_f0 = 0x61;
    local_ec = 0x20;
    local_e8 = 0;
    local_e4 = 0x1a;
    local_e0 = 0x2b;
    local_dc = 10;
    local_d8 = 0x31;
    local_d4 = 0x2d;
    local_d0 = 0xc;
    local_cc = 0xb;
    local_c8 = 2;
    local_c4 = 0x1a;
    local_c0 = 0xc;
    local_bc = 0x61;
    local_b8 = 0x1a;
    local_b4 = 0x74;
    local_b0 = 0x28;
    local_ac = 0x35;
    local_a8 = 0x2a;
    local_a4 = 0x61;
    local_a0 = 0x61;
    local_9c = 0x2c;
    local_98 = 7;
    local_94 = 0x29;
    local_90 = 0x20;
    local_8c = 0x38;
    local_79 = '\0';
    local_12c = 0x45;
    for (local_13c = 0; local_13c < 0x28; local_13c = local_13c + 1) {
      local_13d = (byte) local_12c ^ (byte)local_128[local_13c];
      strncat(&local_79,(char *)&local_13d,1);
    }
  }
  else {
    fwrite("\nHmmm, that seems wrong",1,0x17,stdout);
  }
  fputc(10,stdout);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}