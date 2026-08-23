rule Detect_Crypto_Elements {
    meta:
        description = "Detects Bitcoin, Litecoin, Monero, Ethereum, Solana, Dogecoin, USDT (ERC-20/TRC-20) addresses"

    strings:
        $bitcoin_legacy = /\b1[a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9]{24,33}\b/
        $bitcoin_p2sh = /\b3[a-km-zA-HJ-NP-Z1-9][a-km-zA-HJ-NP-Z1-9]{24,33}\b/
        $bitcoin_bech32 = /\bbc1q[a-z0-9]{38,58}\b/
        $bitcoin_taproot = /\bbc1p[a-z0-9]{58}\b/
        // bitcoin_txid also works for ltc and monero TXID
        $bitcoin_txid = /\b[a-fA-F0-9]{64}\b/
        $monero = /\b4[0-9AB][a-km-zA-HJ-NP-Z1-9]{93}\b/
        //$litecoin_legacy = /\bL[a-km-zA-HJ-NP-Z1-9]*[0-9][a-km-zA-HJ-NP-Z1-9]{25,32}\b/
        $litecoin_legacy = /\bL[a-km-zA-HJ-NP-Z1-9]{32,33}\b/
        $litecoin_bech32 = /\bltc1[a-z0-9]{39,59}\b/
        $privateKeyBIP38 = /\b6P[a-km-zA-HJ-NP-Z1-9]{56}\b/
        $privateKeyEscapeBIP38 = /\b6\x00P\x00([a-km-zA-HJ-NP-Z1-9]\x00){56}\b/
        $privateKeyWIFuncompressed = /\b5[a-km-zA-HJ-NP-Z1-9]{50}\b/
        $privateKeyEscapeWIFuncompressed = /\b5\x00([a-km-zA-HJ-NP-Z1-9]\x00){50}\b/
        $privateKeyWIFcompressed = /\b[KL][a-km-zA-HJ-NP-Z1-9]{51}\b/
        $privateKeyEscapeWIFcompressed = /\b[KL]\x00([a-km-zA-HJ-NP-Z1-9]\x00){51}\b/
        $privateWalletNodeBIP32 = /\bxprv[a-km-zA-HJ-NP-Z1-9]{107,108}\b/
        $privateEscapeWalletNodeBIP32 = /\bx\x00p\x00r\x00v\x00([a-km-zA-HJ-NP-Z1-9]\x00){107,108}\b/
        $publicWalletNodeBIP32 = /\bxpub[a-km-zA-HJ-NP-Z1-9]{107,108}\b/
        $publicEscapeWalletNodeBIP32 = /\bx\x00p\x00u\x00b\x00([a-km-zA-HJ-NP-Z1-9]\x00){107,108}\b/
        $ethereum_address = /\b0x[a-fA-F0-9]{40}\b/
        $ethereum_address_unicode = /\b0\x00x\x00([a-fA-F0-9]\x00){40}\b/
        $ethereum_txid = /\b0x[a-fA-F0-9]{64}\b/
        // Solana addresses: Ed25519 public key, base58, 43-44 chars
        $solana_address = /\b[1-9A-HJ-NP-Za-km-z]{43,44}\b/
        $solana_txid = /\b[1-9A-HJ-NP-Za-km-z]{86,88}\b/
        // Dogecoin: legacy addresses start with 'D', P2SH start with 'A'
        $dogecoin_legacy = /\bD[a-km-zA-HJ-NP-Z1-9]{25,33}\b/
        $dogecoin_multisig = /\bA[a-km-zA-HJ-NP-Z1-9]{33}\b/
        // USDT TRC-20 (Tron): addresses start with 'T', 34 chars total
        // USDT ERC-20 (Ethereum) and BEP-20 (BSC) are covered by $ethereum_address
        $tron_address = /\bT[a-km-zA-HJ-NP-Z1-9]{33}\b/

    condition:
         filesize < 20000MB and
         (
            $bitcoin_legacy or $bitcoin_p2sh or $bitcoin_bech32 or $bitcoin_taproot or $bitcoin_txid or $monero or $litecoin_legacy or $litecoin_bech32 or
            $privateKeyBIP38 or $privateKeyEscapeBIP38 or $privateKeyWIFuncompressed or $privateKeyEscapeWIFuncompressed or
            $privateKeyWIFcompressed or $privateKeyEscapeWIFcompressed or $privateWalletNodeBIP32 or $privateEscapeWalletNodeBIP32 or
            $publicWalletNodeBIP32 or $publicEscapeWalletNodeBIP32 or $ethereum_address or $ethereum_address_unicode or $ethereum_txid or
            $solana_address or $solana_txid or $dogecoin_legacy or $dogecoin_multisig or $tron_address
         )
}
