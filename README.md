# ZKP-Project
KZG polynomial commitment


Generate gt funkcija za generisanje Gt grupe koja se dobije bilinearnim uparivanjem vec postojece grupe.
Setup je funkcija za generisanje trusted setup sa bilinearnim uparivanjem //to ne radi jer koristi bilinearno uparivanje koje nije implementirano
Setup druga uzima kvec podesene parametre i pravi trusted setup tj. public key
Commit commituje public key
Generate witness generise svedoka pri proveravanju
Verify polinom proverava da li je commit zapraavo commit polinoma
Verify eval to jos ne radi
