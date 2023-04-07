# Micro ECC make_key
Simple example of the [micro-ecc library](https://github.com/kmackay/micro-ecc).

Generate private/public key pair.
Then compressed and decompress the public key, and test if the public key and the decompressed key are equals.

*ATTENTION:* This program will not work on m3 nodes! Works only on devices that have the Hardware Random Number Generator (HWRNG)

See [this link](http://doc.riot-os.org/group__pkg__micro__ecc.html) for more info 