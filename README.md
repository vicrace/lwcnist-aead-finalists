# NIST-LWC-finalists-GPU

GPU Implementation of Authenticated Encryption with Associate Data (AEAD) Finalists Candidates in NIST Lightweight Cryptography Standardization. 
Each AEAD consist of 3 different folders:

1. Parallel Granularity folder consist techniques for coarse-grain, fine-grain (only in Photon, Grain128, Elephant, Gift-COFB and Xoodyak), memory structure optimization, and other specific techniques.
2. Coalesced folder consist of coalesced memory access technique.
3. Concurrent folder consist of concurent kernel technique.
