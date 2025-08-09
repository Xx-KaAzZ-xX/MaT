rule Detect_Files_Of_Interest {
    meta:
        description = "Detects .onion URLs, SSH key pairs"

    strings:
        $onion_url = /\b[a-z2-7]{16,56}\.onion\b/
        $rsa_private_key = /-----BEGIN RSA PRIVATE KEY-----[A-Za-z0-9+\/=\r\n]{800,4000}-----END RSA PRIVATE KEY-----/
        $dsa_private_key = /-----BEGIN DSA PRIVATE KEY-----[A-Za-z0-9+\/=\r\n]{600,2500}-----END DSA PRIVATE KEY-----/
        $ec_private_key = /-----BEGIN EC PRIVATE KEY-----[A-Za-z0-9+\/=\r\n]{150,1000}-----END EC PRIVATE KEY-----/
        $openssh_private_key = /-----BEGIN OPENSSH PRIVATE KEY-----[A-Za-z0-9+\/=\r\n]{100,2000}-----END OPENSSH PRIVATE KEY-----/
        $pgp_pub = /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]{100,}-----END PGP PUBLIC KEY BLOCK-----/
        $pgp_priv = /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{100,}-----END PGP PRIVATE KEY BLOCK-----/

        

    condition:
        filesize < 4000MB and
        any of them
}
