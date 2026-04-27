echo -n "0123456789ABCDEF" | xxd -r -p | \
/usr/local/bin/openssl enc -des-ecb -K 133457799BBCDFF1 -nosalt -nopad | xxd -p
