void xorit(long inp1,long inp2)
{
  int i;
  
  for (i = 0; i < 0x10; i = i + 1) {
    *(byte *)(inp1 + i) =*(byte *)(inp1 + i) ^ *(byte *)(inp2 + i % 0x10);
  }
  return;
}


undefined4 main(void)
{
  int i;
  undefined local_98 [120];
  size_t local_20;
  char *input_ptr;
  undefined4 local_c;
  
  local_c = 0;
  ignore_me_init_buffering();
  ignore_me_init_signal();
  puts("Some people say xor encryption is not secure. That is obviously a lie.");
  puts(
      "What if i told you we can use TWO seperate keys for our encryption, and we keep the keys seuc re on our server? No one will ever figure that out!"
      );
  puts("EPT presents, THE SECURE(tm) XOR ENCRYPT0R!");
  input_ptr = (char *)malloc(0xa0);
  printf("Enter ciphertext\n> ");
  fgets(input_ptr,0xa0,stdin); //size 160 from stdin to input_ptr
  local_20 = strlen(input_ptr);
  for (i = 0; (unsigned long)(long)i <= (local_20 >> 4); i = i + 1) { //
    xorit(input_ptr + (i << 4), keys + (long)(i % 2) * 0x10);
  }
  memcpy(local_98,input_ptr,local_20); // copy input_ptr to local_98 (size local_20)
  printf("the results:\n");
  write(1,local_98,local_20);
  return local_c;
}