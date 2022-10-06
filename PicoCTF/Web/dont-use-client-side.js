function verify() {
    checkpass = document.getElementById("pass").value;
    //picoCTF{no_clients_plz_b706c5}
    if (checkpass.substring(0, 4) == 'pico') {
      if (checkpass.substring(24, 28) == '706c') {
        if (checkpass.substring(4, 8) == 'CTF{') {
         if (checkpass.substring(16, 20) == 'ts_p') {
          if (checkpass.substring(12, 16) == 'lien') {
            if (checkpass.substring(20, 24) == 'lz_b') {
              if (checkpass.substring(8, 12) == 'no_c') {
                if (checkpass.substring(28, 32) == '5}') {
                  alert("Password Verified")
                  }
                }
              }
      
            }
          }
        }
      }
    }
    else {
      alert("Incorrect password");
    }
    
  }