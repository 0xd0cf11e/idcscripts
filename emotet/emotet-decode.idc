auto decode = 0x401b70; // Address may be different based on the file being analyzed

auto xref;

// Find all code references (xref) to the decode function
for(xref = RfirstB(decode); xref != BADADDR; xref = RnextB(decode,xref)){
    Message("xref: %x\n",xref);

    auto i = 0;
    auto ecx = 0; // ecx holds the offset to the encrypted data
    auto edx = 0; // edx holds the key
    auto inst = xref;
    auto op, s, comm;

    // Iterating backwards from the xref
    // through max 100 instructions to find the values
    // moved to registers ecx and edx
    while((i < 100) & ((ecx == 0) || (edx == 0))){
      inst = FindCode(inst,0x00); // flag set to backwards
      op = GetDisasm(inst); // get the disassembly string to match
      if(ecx == 0){
        s = strstr(op, "mov     ecx");
        if(s == 0){
          comm = inst; // save instruction addr for commenting
          ecx = Dword(inst+0x1);
          Message("ecx: %x\n",ecx);
        }
      }
      if(edx == 0){
        s = strstr(op, "mov     edx");
        if(s == 0){
          edx = Dword(inst+0x1);
          Message("edx: %x\n",edx);
        }
      }
      i++;
    }

    if((ecx != 0) & (edx != 0)){
      // Dword(Offset) xor key = string length
      // ecx = Offset
      // edx = key
      auto strLen = Dword(ecx) ^ edx;
      Message("String length: %d \n",strLen);

      // reset original bytes
      auto k;
      auto l = ecx+0x4;
      auto decoded = ecx+0x4;
      for(k=0; k<strLen; k++){
        PatchByte(l,GetOriginalByte(l));
        l++;
      }

      // xor the string and Patch the bytes
      auto d;
      auto j = 0;
      Message("String: ");
      while(j < strLen){
        ecx = ecx + 0x4;
        d = Dword(ecx) ^ edx;
        PatchDword(ecx,d);
        MakeStr(decoded,decoded+strLen);
        MakeComm(comm,Name(decoded));
        Message("%s",d);
        j = j + 0x4;
      }
    }
    else {
      Message("No ecx or edx found. \n");
    }


    Message("\n\n");


}
