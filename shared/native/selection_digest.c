/* SPDX-License-Identifier: GPL-3.0-or-later
 * SHA-256 of authenticated public snapshot bytes, not a MAC or cookie issuer.
 * Portable to the standalone parser test; no external crypto/JSON ABI.
 */
static uint32_t selection_rotate(uint32_t x, unsigned n) { return (x>>n)|(x<<(32-n)); }
static void selection_sha_block(uint32_t state[8], const unsigned char block[64]) {
    static const uint32_t constants[64] = {
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
    };
    uint32_t words[64], a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],f=state[5],g=state[6],h=state[7];
    unsigned i;
    for (i=0;i<16;++i) words[i]=((uint32_t)block[4*i]<<24)|((uint32_t)block[4*i+1]<<16)|((uint32_t)block[4*i+2]<<8)|block[4*i+3];
    for (i=16;i<64;++i) {
        uint32_t x=words[i-15],y=words[i-2];
        words[i]=words[i-16]+(selection_rotate(x,7)^selection_rotate(x,18)^(x>>3))+words[i-7]+
            (selection_rotate(y,17)^selection_rotate(y,19)^(y>>10));
    }
    for (i=0;i<64;++i) {
        uint32_t t1=h+(selection_rotate(e,6)^selection_rotate(e,11)^selection_rotate(e,25))+((e&f)^(~e&g))+constants[i]+words[i];
        uint32_t t2=(selection_rotate(a,2)^selection_rotate(a,13)^selection_rotate(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}
int delivery_selection_digest(const unsigned char *body, size_t length, char digest[65]) {
    uint32_t state[8]={0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    unsigned char tail[128]={0};
    static const char hex[]="0123456789abcdef";
    size_t offset=0,remaining;
    uint64_t bits;
    unsigned i;
    if (!digest || (!body && length) || length>UINT64_MAX/8) return 0;
    while (length-offset>=64) { selection_sha_block(state,body+offset);offset+=64; }
    remaining=length-offset;
    if (remaining) memcpy(tail,body+offset,remaining);
    tail[remaining]=0x80;bits=(uint64_t)length*8;
    for (i=0;i<8;++i) tail[(remaining<56 ? 56 : 120)+i]=(unsigned char)(bits>>(56-8*i));
    selection_sha_block(state,tail);
    if (remaining>=56) selection_sha_block(state,tail+64);
    for (i=0;i<32;++i) {
        unsigned char value=(unsigned char)(state[i/4]>>(24-8*(i%4)));
        digest[2*i]=hex[value>>4];digest[2*i+1]=hex[value&15];
    }
    digest[64]=0;return 1;
}
