
#define AUTH_LOOP_COUNT 8
// NAO PODE SER NEM O PRIMEIRO, E NEM O ULTIMO
#define AUTH_LOOP_VERIFY 3

#define AUTH_REGISTERS_N 4
#define AUTH_RANDOMS_N 128

#define AUTH_REGISTER_0 0x0000000000000000ULL
#define AUTH_REGISTER_1 0x0000000000000000ULL
#define AUTH_REGISTER_2 0x0000000000000000ULL
#define AUTH_REGISTER_3 0x0000000000000000ULL

#define AUTH_0_ADD_1_SHIFT 4
#define AUTH_2_ADD_3_SHIFT 3
#define AUTH_1_ADD 0x34234340ULL
#define AUTH_3_ADD 0x32432432ULL

#define AUTH_INIT_0 0
#define AUTH_INIT_1 3
#define AUTH_INIT_2 1
#define AUTH_INIT_3 2

#define AUTH_VERIFY_0 0
#define AUTH_VERIFY_1 3
#define AUTH_VERIFY_2 1
#define AUTH_VERIFY_3 2

#define XTUN_AUTH_SIZE ((AUTH_REGISTERS_N + AUTH_RANDOMS_N)*sizeof(u64))

typedef struct xtun_auth_s {
    u64 verify   [AUTH_REGISTERS_N]; // COMO OS REGISTROS TERMINAM
    u64 randoms  [AUTH_RANDOMS_N];
} xtun_auth_s;

static u16 xtun_auth_key_ (const u16 secret, xtun_auth_s* const auth, bool save) {

    u64 register0 = AUTH_REGISTER_0 + secret + auth->randoms[AUTH_INIT_0];
    u64 register1 = AUTH_REGISTER_1 + secret + auth->randoms[AUTH_INIT_1];
    u64 register2 = AUTH_REGISTER_2 + secret + auth->randoms[AUTH_INIT_2];
    u64 register3 = AUTH_REGISTER_3 + secret + auth->randoms[AUTH_INIT_3];

    for (uint c = AUTH_LOOP_COUNT; c; c--) {

        register0 += auth->randoms[register3 & (AUTH_RANDOMS_N - 1)];
        register1 += auth->randoms[register2 & (AUTH_RANDOMS_N - 1)];
        register2 += auth->randoms[register1 & (AUTH_RANDOMS_N - 1)];
        register3 += auth->randoms[register0 & (AUTH_RANDOMS_N - 1)];

        register0 += auth->randoms[register1 & (AUTH_RANDOMS_N - 1)];
        register1 += auth->randoms[register2 & (AUTH_RANDOMS_N - 1)];
        register2 += auth->randoms[register3 & (AUTH_RANDOMS_N - 1)];
        register3 += auth->randoms[register0 & (AUTH_RANDOMS_N - 1)];

        if (c == AUTH_LOOP_VERIFY) {
            if (save) {
                auth->verify[AUTH_VERIFY_0] = register0;
                auth->verify[AUTH_VERIFY_1] = register1;
                auth->verify[AUTH_VERIFY_2] = register2;
                auth->verify[AUTH_VERIFY_3] = register3;
            } else
                save =
                    register0 == auth->verify[AUTH_VERIFY_0] &&
                    register1 == auth->verify[AUTH_VERIFY_1] &&
                    register2 == auth->verify[AUTH_VERIFY_2] &&
                    register3 == auth->verify[AUTH_VERIFY_3];
        }

        register0 += register1 >> AUTH_0_ADD_1_SHIFT;
        register2 += register3 >> AUTH_2_ADD_3_SHIFT;
        register1 += AUTH_1_ADD;
        register3 += AUTH_3_ADD;
    }

    register0 += register1;
    register0 += register2;
    register0 += register3;
    register0 += register0 >> 32;
    register0 += register0 >> 16;
    register0 &= 0xFFFFULL;
    register0 += !register0;
    // RETORNA 0 SE FALHOU, OU UMA KEY SE SUCESSO
    register0 *= save;

    return (u16)register0;
}

static inline u16 xtun_auth_key_gen (const u16 secret, xtun_auth_s* const auth) {

    return xtun_auth_key_(secret, auth, true);
}

static inline u16 xtun_auth_key_check (const u16 secret, xtun_auth_s* const auth) {

    return xtun_auth_key_(secret, auth, false);
}
